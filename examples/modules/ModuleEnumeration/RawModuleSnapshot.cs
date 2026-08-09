using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ModuleEnumeration;

/// <summary>Minimal raw Toolhelp32 example that exposes MODULEENTRY32 layout and deterministic snapshot cleanup.</summary>
internal static unsafe partial class RawModuleSnapshot
{
    private const uint Th32CsSnapModule = 0x00000008;
    private const uint Th32CsSnapModule32 = 0x00000010;
    private const int ErrorNoMoreFiles = 18;

    internal static IReadOnlyList<RawModuleInfo> ReadFirstTwoModules(uint processId)
    {
        var snapshot = CreateToolhelp32Snapshot(Th32CsSnapModule | Th32CsSnapModule32, processId);

        if (snapshot == new IntPtr(-1))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        try
        {
            var modules = new List<RawModuleInfo>();
            var entry = CreateModuleEntry();

            if (!Module32First(snapshot, ref entry))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            modules.Add(ToInfo(entry));
            entry = CreateModuleEntry();

            if (Module32Next(snapshot, ref entry))
            {
                modules.Add(ToInfo(entry));
            }
            else if (Marshal.GetLastPInvokeError() != ErrorNoMoreFiles)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            return modules;
        }
        finally
        {
            _ = CloseHandle(snapshot);
        }
    }

    private static ModuleEntry32Raw CreateModuleEntry() => new()
    {
        // dwSize is mandatory before Module32First/Module32Next; pointer fields make its native layout architecture-sensitive.
        Size = (uint)Marshal.SizeOf<ModuleEntry32Raw>(),
    };

    private static RawModuleInfo ToInfo(ModuleEntry32Raw entry) => new(
        entry.GetModuleName(),
        entry.GetExecutablePath(),
        unchecked((nuint)entry.BaseAddress),
        entry.BaseSize,
        entry.ProcessId);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ModuleEntry32Raw
    {
        internal uint Size;
        internal uint ModuleId;
        internal uint ProcessId;
        internal uint GlobalUsageCount;
        internal uint ProcessUsageCount;
        internal nint BaseAddress;
        internal uint BaseSize;
        internal nint ModuleHandle;
        private fixed char moduleName[256];
        private fixed char executablePath[260];

        internal string GetModuleName()
        {
            fixed (char* name = moduleName)
            {
                return new string(name);
            }
        }

        internal string GetExecutablePath()
        {
            fixed (char* path = executablePath)
            {
                return new string(path);
            }
        }
    }

    // Native: HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID).
    [LibraryImport("kernel32.dll", EntryPoint = "CreateToolhelp32Snapshot", SetLastError = true)]
    private static partial IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    // Native: BOOL Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme).
    [LibraryImport("kernel32.dll", EntryPoint = "Module32FirstW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Module32First(IntPtr snapshot, ref ModuleEntry32Raw entry);

    // Native: BOOL Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme).
    [LibraryImport("kernel32.dll", EntryPoint = "Module32NextW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Module32Next(IntPtr snapshot, ref ModuleEntry32Raw entry);

    // Native: BOOL CloseHandle(HANDLE hObject). Every real snapshot handle must be closed.
    [LibraryImport("kernel32.dll", EntryPoint = "CloseHandle")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);
}

internal sealed record RawModuleInfo(string Name, string Path, nuint BaseAddress, uint Size, uint ProcessId);
