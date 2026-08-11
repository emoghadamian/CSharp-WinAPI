using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Interop.Advapi32;

/// <summary>Raw declarations for documented read-only access-token APIs.</summary>
internal static partial class Advapi32Native
{
    [LibraryImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial uint GetNamedSecurityInfo(
        string objectName,
        SecurityObjectType objectType,
        SecurityInformation securityInformation,
        out nint owner,
        out nint group,
        out nint dacl,
        nint sacl,
        out SafeSecurityDescriptorHandle securityDescriptor);

    [LibraryImport("advapi32.dll", EntryPoint = "GetSecurityDescriptorOwner", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetSecurityDescriptorOwner(SafeSecurityDescriptorHandle securityDescriptor, out nint owner, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);

    [LibraryImport("advapi32.dll", EntryPoint = "GetSecurityDescriptorGroup", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetSecurityDescriptorGroup(SafeSecurityDescriptorHandle securityDescriptor, out nint group, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);

    [LibraryImport("advapi32.dll", EntryPoint = "GetSecurityDescriptorDacl", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetSecurityDescriptorDacl(SafeSecurityDescriptorHandle securityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool present, out nint dacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);

    [LibraryImport("advapi32.dll", EntryPoint = "GetSecurityDescriptorControl", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetSecurityDescriptorControl(SafeSecurityDescriptorHandle securityDescriptor, out ushort control, out uint revision);

    [LibraryImport("advapi32.dll", EntryPoint = "GetAclInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetAclInformation(nint acl, out AclSizeInformationNative information, uint informationLength, AclInformationClass informationClass);

    [LibraryImport("advapi32.dll", EntryPoint = "GetAce", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetAce(nint acl, uint aceIndex, out nint ace);

    [LibraryImport("advapi32.dll", EntryPoint = "IsValidSid")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsValidSid(nint sid);

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ConvertSidToStringSid(nint sid, out nint stringSid);

    [LibraryImport("advapi32.dll", EntryPoint = "DuplicateToken", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DuplicateToken(SafeTokenHandle existingToken, SecurityImpersonationLevel impersonationLevel, out SafeTokenHandle duplicateToken);

    [LibraryImport("advapi32.dll", EntryPoint = "AccessCheck", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool AccessCheck(nint securityDescriptor, SafeTokenHandle clientToken, uint desiredAccess, in GenericMappingNative genericMapping, nint privilegeSet, ref uint privilegeSetLength, out uint grantedAccess, [MarshalAs(UnmanagedType.Bool)] out bool accessStatus);

    [LibraryImport("advapi32.dll", EntryPoint = "MapGenericMask")]
    internal static partial void MapGenericMask(ref uint accessMask, in GenericMappingNative genericMapping);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool OpenProcessToken(SafeProcessHandle process, TokenAccessRights desiredAccess, out SafeTokenHandle token);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool OpenProcessToken(nint process, TokenAccessRights desiredAccess, out SafeTokenHandle token);

    [LibraryImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetTokenInformation(SafeTokenHandle token, TokenInformationClass informationClass, nint tokenInformation, uint tokenInformationLength, out uint returnLength);

    [LibraryImport("advapi32.dll", EntryPoint = "LookupPrivilegeNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool LookupPrivilegeName(string? systemName, in LuidNative luid, char* name, ref uint characterCount);

    [LibraryImport("advapi32.dll", EntryPoint = "GetLengthSid")]
    internal static partial uint GetLengthSid(nint sid);
}
