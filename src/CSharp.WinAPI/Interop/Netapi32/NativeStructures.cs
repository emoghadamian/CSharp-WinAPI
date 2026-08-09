using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Netapi32;

[StructLayout(LayoutKind.Sequential)]
internal struct LocalGroupInfo0Native
{
    internal IntPtr Name;
}

[StructLayout(LayoutKind.Sequential)]
internal struct LocalGroupMembersInfo2Native
{
    internal IntPtr Sid;
    internal SidNameUse SidUsage;
    internal IntPtr DomainAndName;
}

/// <summary>Native SID_NAME_USE values returned by NetLocalGroupGetMembers.</summary>
internal enum SidNameUse
{
    User = 1,
    Group = 2,
    Domain = 3,
    Alias = 4,
    WellKnownGroup = 5,
    DeletedAccount = 6,
    Invalid = 7,
    Unknown = 8,
    Computer = 9,
    Label = 10,
}
