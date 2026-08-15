using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Processes;

/// <summary>
/// Provides read-only process inspection through Toolhelp32 snapshots and query-limited process handles.
/// </summary>
public sealed class ProcessInspector
{
    private const int ErrorNotFound = 1168;
    private const uint ImageFileNameWin32Path = 0;
    private const int MaximumExtendedPathLength = 32768;
    private const ushort ImageFileMachineUnknown = 0x0000;
    private const ushort ImageFileMachineI386 = 0x014c;
    private const ushort ImageFileMachineArm = 0x01c0;
    private const ushort ImageFileMachineArmNt = 0x01c4;
    private const ushort ImageFileMachineIa64 = 0x0200;
    private const ushort ImageFileMachineAmd64 = 0x8664;
    private const ushort ImageFileMachineArm64 = 0xaa64;

    /// <summary>Enumerates the processes visible in a point-in-time Toolhelp32 snapshot.</summary>
    public IReadOnlyList<ProcessInfo> EnumerateProcesses()
    {
        using var snapshot = Kernel32Native.CreateToolhelp32Snapshot(Kernel32Native.Th32CsSnapProcess, processId: 0);

        if (snapshot.IsInvalid)
        {
            throw CreateLastErrorException(nameof(Kernel32Native.CreateToolhelp32Snapshot));
        }

        var processes = new List<ProcessInfo>();
        var entry = CreateProcessEntry();

        if (!Kernel32Native.Process32First(snapshot, ref entry))
        {
            var errorCode = Marshal.GetLastPInvokeError();

            if (errorCode == Kernel32Native.ErrorNoMoreFiles)
            {
                return processes;
            }

            throw new ProcessInspectionException(nameof(Kernel32Native.Process32First), errorCode);
        }

        while (true)
        {
            processes.Add(InspectEntry(entry));
            entry = CreateProcessEntry();

            if (Kernel32Native.Process32Next(snapshot, ref entry))
            {
                continue;
            }

            var errorCode = Marshal.GetLastPInvokeError();

            if (errorCode == Kernel32Native.ErrorNoMoreFiles)
            {
                return processes;
            }

            throw new ProcessInspectionException(nameof(Kernel32Native.Process32Next), errorCode);
        }
    }

    /// <summary>Locates one process in a fresh Toolhelp32 snapshot and returns its read-only information.</summary>
    /// <exception cref="ProcessInspectionException">Thrown when no process with the supplied PID is in the snapshot.</exception>
    public ProcessInfo InspectProcess(uint processId)
    {
        foreach (var process in EnumerateProcesses())
        {
            if (process.ProcessId == processId)
            {
                return process;
            }
        }

        throw new ProcessInspectionException(nameof(InspectProcess), ErrorNotFound);
    }

    private static ProcessEntry32Native CreateProcessEntry() => new()
    {
        Size = (uint)Marshal.SizeOf<ProcessEntry32Native>(),
    };

    private static ProcessInfo InspectEntry(ProcessEntry32Native entry)
    {
        var name = entry.GetExecutableFileName();
        var diagnostics = new ProcessInspectionDiagnosticsBuilder();
        var sessionId = TryGetSessionId(entry.ProcessId, out var sessionDiagnostic);
        diagnostics.SetSessionId(sessionDiagnostic);

        using var process = Kernel32Native.OpenProcess(
            ProcessAccessRights.QueryLimitedInformation,
            inheritHandle: false,
            entry.ProcessId);

        if (process.IsInvalid)
        {
            var errorCode = Marshal.GetLastPInvokeError();
            diagnostics.MarkExtendedQueriesNotAttempted();
            return new ProcessInfo(
                entry.ProcessId,
                entry.ParentProcessId,
                name,
                ExecutablePath: null,
                CreationTimeUtc: null,
                sessionId,
                Architecture: null,
                InspectionErrorCode: diagnostics.FirstNativeErrorCode ?? errorCode)
            {
                Diagnostics = diagnostics.Build(),
            };
        }

        var executablePath = TryGetExecutablePath(process, out var imagePathDiagnostic);
        diagnostics.SetImagePath(imagePathDiagnostic);
        var creationTime = TryGetCreationTime(process, out var creationTimeDiagnostic);
        diagnostics.SetCreationTime(creationTimeDiagnostic);
        var architecture = TryGetArchitecture(process, out var architectureDiagnostic);
        diagnostics.SetArchitecture(architectureDiagnostic);

        return new ProcessInfo(
            entry.ProcessId,
            entry.ParentProcessId,
            name,
            executablePath,
            creationTime,
            sessionId,
            architecture,
            diagnostics.FirstNativeErrorCode)
        {
            Diagnostics = diagnostics.Build(),
        };
    }

    private static uint? TryGetSessionId(uint processId, out ProcessQueryDiagnostic diagnostic)
    {
        if (Kernel32Native.ProcessIdToSessionId(processId, out var sessionId))
        {
            diagnostic = ProcessQueryDiagnostic.Succeeded;
            return sessionId;
        }

        diagnostic = ProcessQueryDiagnostic.Failed(Marshal.GetLastPInvokeError());
        return null;
    }

    private static unsafe string? TryGetExecutablePath(SafeProcessHandle process, out ProcessQueryDiagnostic diagnostic)
    {
        var buffer = new char[MaximumExtendedPathLength];

        fixed (char* path = buffer)
        {
            var pathLength = (uint)buffer.Length;

            if (Kernel32Native.QueryFullProcessImageName(process, ImageFileNameWin32Path, path, ref pathLength))
            {
                diagnostic = ProcessQueryDiagnostic.Succeeded;
                return new string(buffer, 0, checked((int)pathLength));
            }
        }

        diagnostic = ProcessQueryDiagnostic.Failed(Marshal.GetLastPInvokeError());
        return null;
    }

    private static DateTimeOffset? TryGetCreationTime(SafeProcessHandle process, out ProcessQueryDiagnostic diagnostic)
    {
        if (!Kernel32Native.GetProcessTimes(process, out var creationTime, out _, out _, out _))
        {
            diagnostic = ProcessQueryDiagnostic.Failed(Marshal.GetLastPInvokeError());
            return null;
        }

        diagnostic = ProcessQueryDiagnostic.Succeeded;
        return new DateTimeOffset(DateTime.FromFileTimeUtc(creationTime.ToInt64()));
    }

    private static ProcessArchitectureInfo? TryGetArchitecture(SafeProcessHandle process, out ProcessQueryDiagnostic diagnostic)
    {
        try
        {
            if (Kernel32Native.IsWow64Process2(process, out var processMachine, out var nativeMachine))
            {
                var isWow64 = processMachine != ImageFileMachineUnknown;
                diagnostic = ProcessQueryDiagnostic.Succeeded;
                return new ProcessArchitectureInfo(
                    isWow64 ? MapArchitecture(processMachine) : MapArchitecture(nativeMachine),
                    MapArchitecture(nativeMachine),
                    isWow64);
            }

            var errorCode = Marshal.GetLastPInvokeError();

            if (errorCode != Kernel32Native.ErrorCallNotImplemented)
            {
                diagnostic = ProcessQueryDiagnostic.Failed(errorCode);
                return null;
            }
        }
        catch (EntryPointNotFoundException)
        {
            // IsWow64Process2 is unavailable before Windows 10 version 1709.
        }

        if (!Kernel32Native.IsWow64Process(process, out var wow64Process))
        {
            diagnostic = ProcessQueryDiagnostic.Failed(Marshal.GetLastPInvokeError());
            return null;
        }

        var nativeArchitecture = MapArchitecture(RuntimeInformation.OSArchitecture);
        diagnostic = ProcessQueryDiagnostic.Succeeded;
        return new ProcessArchitectureInfo(
            wow64Process != 0 ? ProcessArchitecture.X86 : nativeArchitecture,
            nativeArchitecture,
            wow64Process != 0);
    }

    private static ProcessArchitecture MapArchitecture(ushort machine) => machine switch
    {
        ImageFileMachineI386 => ProcessArchitecture.X86,
        ImageFileMachineArm or ImageFileMachineArmNt => ProcessArchitecture.Arm,
        ImageFileMachineIa64 => ProcessArchitecture.Itanium,
        ImageFileMachineAmd64 => ProcessArchitecture.X64,
        ImageFileMachineArm64 => ProcessArchitecture.Arm64,
        _ => ProcessArchitecture.Unknown,
    };

    private static ProcessArchitecture MapArchitecture(Architecture architecture) => architecture switch
    {
        Architecture.X86 => ProcessArchitecture.X86,
        Architecture.X64 => ProcessArchitecture.X64,
        Architecture.Arm => ProcessArchitecture.Arm,
        Architecture.Arm64 => ProcessArchitecture.Arm64,
        _ => ProcessArchitecture.Unknown,
    };

    private static ProcessInspectionException CreateLastErrorException(string operation) =>
        new(operation, Marshal.GetLastPInvokeError());
}
