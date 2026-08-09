using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Modules;

/// <summary>Provides read-only per-process module enumeration through Toolhelp32 snapshots.</summary>
public sealed class ModuleInspector
{
    private const int ErrorBadLength = 24;
    private const int ErrorInvalidData = 13;
    private const int MaximumSnapshotAttempts = 3;

    /// <summary>Enumerates executable and DLL modules loaded by a process at the time of its snapshot.</summary>
    /// <exception cref="ModuleInspectionException">Thrown when the module snapshot cannot be created or enumerated.</exception>
    public IReadOnlyList<ModuleInfo> EnumerateProcessModules(uint processId)
    {
        using var snapshot = CreateModuleSnapshot(processId);
        var modules = new List<ModuleInfo>();
        var entry = CreateModuleEntry();

        if (!Kernel32Native.Module32First(snapshot, ref entry))
        {
            var errorCode = Marshal.GetLastPInvokeError();

            if (errorCode == Kernel32Native.ErrorNoMoreFiles)
            {
                return modules;
            }

            throw new ModuleInspectionException(nameof(Kernel32Native.Module32First), errorCode);
        }

        while (true)
        {
            modules.Add(ToModuleInfo(entry));
            entry = CreateModuleEntry();

            if (Kernel32Native.Module32Next(snapshot, ref entry))
            {
                continue;
            }

            var errorCode = Marshal.GetLastPInvokeError();

            if (errorCode == Kernel32Native.ErrorNoMoreFiles)
            {
                return modules;
            }

            throw new ModuleInspectionException(nameof(Kernel32Native.Module32Next), errorCode);
        }
    }

    private static SafeSnapshotHandle CreateModuleSnapshot(uint processId)
    {
        var flags = Kernel32Native.Th32CsSnapModule | Kernel32Native.Th32CsSnapModule32;
        var errorCode = 0;

        for (var attempt = 0; attempt < MaximumSnapshotAttempts; attempt++)
        {
            var snapshot = Kernel32Native.CreateToolhelp32Snapshot(flags, processId);

            if (!snapshot.IsInvalid)
            {
                return snapshot;
            }

            errorCode = Marshal.GetLastPInvokeError();
            snapshot.Dispose();

            if (errorCode != ErrorBadLength)
            {
                throw new ModuleInspectionException(nameof(Kernel32Native.CreateToolhelp32Snapshot), errorCode);
            }
        }

        throw new ModuleInspectionException(nameof(Kernel32Native.CreateToolhelp32Snapshot), errorCode);
    }

    private static ModuleEntry32Native CreateModuleEntry() => new()
    {
        Size = (uint)Marshal.SizeOf<ModuleEntry32Native>(),
    };

    private static ModuleInfo ToModuleInfo(ModuleEntry32Native entry)
    {
        if (!entry.HasCompleteInformation)
        {
            throw new ModuleInspectionException(nameof(ModuleEntry32Native), ErrorInvalidData);
        }

        return new ModuleInfo(
            entry.GetModuleName(),
            entry.GetExecutablePath(),
            unchecked((nuint)entry.BaseAddress),
            entry.BaseSize,
            entry.ProcessId);
    }
}
