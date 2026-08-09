using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Kernel32;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal unsafe struct ModuleEntry32Native
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

    internal bool HasCompleteInformation => Size >= Marshal.SizeOf<ModuleEntry32Native>();
}
