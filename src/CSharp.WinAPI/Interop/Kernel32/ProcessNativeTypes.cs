using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Kernel32;

[Flags]
internal enum ProcessAccessRights : uint
{
    QueryInformation = 0x00000400,
    QueryLimitedInformation = 0x00001000,
}

[StructLayout(LayoutKind.Sequential)]
internal struct FileTimeNative
{
    internal uint LowDateTime;
    internal uint HighDateTime;

    internal long ToInt64() => (long)(((ulong)HighDateTime << 32) | LowDateTime);
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal unsafe struct ProcessEntry32Native
{
    internal uint Size;
    internal uint UsageCount;
    internal uint ProcessId;
    internal nuint DefaultHeapId;
    internal uint ModuleId;
    internal uint ThreadCount;
    internal uint ParentProcessId;
    internal int BasePriority;
    internal uint Flags;
    private fixed char executableFileName[260];

    internal string GetExecutableFileName()
    {
        fixed (char* name = executableFileName)
        {
            return new string(name);
        }
    }
}
