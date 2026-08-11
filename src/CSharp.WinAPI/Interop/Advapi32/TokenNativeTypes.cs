using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Advapi32;

[Flags]
internal enum TokenAccessRights : uint
{
    Query = 0x0008,
}

internal enum TokenInformationClass
{
    User = 1,
    Groups = 2,
    Privileges = 3,
    Type = 8,
    ImpersonationLevel = 9,
    SessionId = 12,
    Elevation = 20,
    IntegrityLevel = 25,
}

[StructLayout(LayoutKind.Sequential)]
internal struct SidAndAttributesNative
{
    internal nint Sid;
    internal uint Attributes;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TokenUserNative
{
    internal SidAndAttributesNative User;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TokenMandatoryLabelNative
{
    internal SidAndAttributesNative Label;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TokenGroupsNative
{
    internal uint GroupCount;
    internal SidAndAttributesNative FirstGroup;
}

[StructLayout(LayoutKind.Sequential)]
internal struct LuidNative
{
    internal uint LowPart;
    internal int HighPart;

    internal ulong ToUInt64() => ((ulong)(uint)HighPart << 32) | LowPart;
}

[StructLayout(LayoutKind.Sequential)]
internal struct LuidAndAttributesNative
{
    internal LuidNative Luid;
    internal uint Attributes;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TokenPrivilegesNative
{
    internal uint PrivilegeCount;
    internal LuidAndAttributesNative FirstPrivilege;
}
