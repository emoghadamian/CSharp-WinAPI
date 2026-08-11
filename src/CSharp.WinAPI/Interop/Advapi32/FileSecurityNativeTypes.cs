using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Advapi32;

[Flags]
internal enum SecurityInformation : uint
{
    Owner = 0x00000001,
    Group = 0x00000002,
    Dacl = 0x00000004,
}

internal enum SecurityObjectType
{
    FileObject = 1,
}

internal enum AclInformationClass
{
    AclRevisionInformation = 1,
    AclSizeInformation = 2,
}

[StructLayout(LayoutKind.Sequential)]
internal struct AclSizeInformationNative
{
    internal uint AceCount;
    internal uint AclBytesInUse;
    internal uint AclBytesFree;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct AclNative
{
    internal byte Revision;
    internal byte Sbz1;
    internal ushort Size;
    internal ushort AceCount;
    internal ushort Sbz2;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct AceHeaderNative
{
    internal byte Type;
    internal byte Flags;
    internal ushort Size;
}
