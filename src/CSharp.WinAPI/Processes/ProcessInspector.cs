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
        var sessionId = TryGetSessionId(entry.ProcessId, out var sessionError);

        using var process = Kernel32Native.OpenProcess(
            ProcessAccessRights.QueryLimitedInformation,
            inheritHandle: false,
            entry.ProcessId);

        if (process.IsInvalid)
        {
            var errorCode = Marshal.GetLastPInvokeError();
            return new ProcessInfo(
                entry.ProcessId,
                entry.ParentProcessId,
                name,
                ExecutablePath: null,
                CreationTimeUtc: null,
                sessionId,
                Architecture: null,
                InspectionErrorCode: sessionError ?? errorCode);
        }

        int? inspectionError = sessionError;
        var executablePath = TryGetExecutablePath(process, ref inspectionError);
        var creationTime = TryGetCreationTime(process, ref inspectionError);
        var architecture = TryGetArchitecture(process, ref inspectionError);

        return new ProcessInfo(
            entry.ProcessId,
            entry.ParentProcessId,
            name,
            executablePath,
            creationTime,
            sessionId,
            architecture,
            inspectionError);
    }

    private static uint? TryGetSessionId(uint processId, out int? errorCode)
    {
        if (Kernel32Native.ProcessIdToSessionId(processId, out var sessionId))
        {
            errorCode = null;
            return sessionId;
        }

        errorCode = Marshal.GetLastPInvokeError();
        return null;
    }

    private static unsafe string? TryGetExecutablePath(SafeProcessHandle process, ref int? inspectionError)
    {
        var buffer = new char[MaximumExtendedPathLength];

        fixed (char* path = buffer)
        {
            var pathLength = (uint)buffer.Length;

            if (Kernel32Native.QueryFullProcessImageName(process, ImageFileNameWin32Path, path, ref pathLength))
            {
                return new string(buffer, 0, checked((int)pathLength));
            }
        }

        CaptureLastError(ref inspectionError);
        return null;
    }

    private static DateTimeOffset? TryGetCreationTime(SafeProcessHandle process, ref int? inspectionError)
    {
        if (!Kernel32Native.GetProcessTimes(process, out var creationTime, out _, out _, out _))
        {
            CaptureLastError(ref inspectionError);
            return null;
        }

        return new DateTimeOffset(DateTime.FromFileTimeUtc(creationTime.ToInt64()));
    }

    private static ProcessArchitectureInfo? TryGetArchitecture(SafeProcessHandle process, ref int? inspectionError)
    {
        try
        {
            if (Kernel32Native.IsWow64Process2(process, out var processMachine, out var nativeMachine))
            {
                var isWow64 = processMachine != ImageFileMachineUnknown;
                return new ProcessArchitectureInfo(
                    isWow64 ? MapArchitecture(processMachine) : MapArchitecture(nativeMachine),
                    MapArchitecture(nativeMachine),
                    isWow64);
            }

            var errorCode = Marshal.GetLastPInvokeError();

            if (errorCode != Kernel32Native.ErrorCallNotImplemented)
            {
                inspectionError ??= errorCode;
                return null;
            }
        }
        catch (EntryPointNotFoundException)
        {
            // IsWow64Process2 is unavailable before Windows 10 version 1709.
        }

        if (!Kernel32Native.IsWow64Process(process, out var wow64Process))
        {
            CaptureLastError(ref inspectionError);
            return null;
        }

        var nativeArchitecture = MapArchitecture(RuntimeInformation.OSArchitecture);
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

    private static void CaptureLastError(ref int? inspectionError) =>
        inspectionError ??= Marshal.GetLastPInvokeError();

    private static ProcessInspectionException CreateLastErrorException(string operation) =>
        new(operation, Marshal.GetLastPInvokeError());
}
