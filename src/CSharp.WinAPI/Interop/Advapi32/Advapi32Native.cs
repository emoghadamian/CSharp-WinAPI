using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Interop.Advapi32;

/// <summary>Raw declarations for documented read-only access-token APIs.</summary>
internal static partial class Advapi32Native
{
    [LibraryImport("advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool OpenProcessToken(SafeProcessHandle process, TokenAccessRights desiredAccess, out SafeTokenHandle token);

    [LibraryImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetTokenInformation(SafeTokenHandle token, TokenInformationClass informationClass, nint tokenInformation, uint tokenInformationLength, out uint returnLength);

    [LibraryImport("advapi32.dll", EntryPoint = "LookupPrivilegeNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool LookupPrivilegeName(string? systemName, in LuidNative luid, char* name, ref uint characterCount);

    [LibraryImport("advapi32.dll", EntryPoint = "IsValidSid")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsValidSid(nint sid);

    [LibraryImport("advapi32.dll", EntryPoint = "GetLengthSid")]
    internal static partial uint GetLengthSid(nint sid);
}
