using System.ComponentModel;
using System.Runtime.InteropServices;

namespace RegistrySecurityInspection;

// A deliberately compact illustration of the managed byte[] and pinning lifetime hidden by RegistrySecurityInspector.
internal static partial class RawRegistrySecurity
{
    private const int ErrorInsufficientBuffer = 122;
    private const uint ReadControl = 0x00020000;
    private const uint DaclSecurityInformation = 0x00000004;
    private static readonly nint HkeyCurrentUser = unchecked((nint)(int)0x80000001);

    internal static string DescribeFirstAce(string subKey)
    {
        var status = RegOpenKeyEx(HkeyCurrentUser, subKey, 0, ReadControl, out var key);
        if (status != 0) throw new Win32Exception(status);

        try
        {
            uint length = 0;
            status = RegGetKeySecurity(key, DaclSecurityInformation, nint.Zero, ref length);
            if (status != ErrorInsufficientBuffer || length == 0) throw new Win32Exception(status);

            var descriptor = new byte[checked((int)length)];
            unsafe
            {
                fixed (byte* bytes = descriptor)
                {
                    var returnedLength = length;
                    status = RegGetKeySecurity(key, DaclSecurityInformation, (nint)bytes, ref returnedLength);
                    if (status != 0) throw new Win32Exception(status);
                    if (!GetSecurityDescriptorDacl((nint)bytes, out var present, out var dacl, out _)) throw new Win32Exception(Marshal.GetLastPInvokeError());
                    if (!present || dacl == nint.Zero) return present ? "NULL DACL" : "absent DACL";
                    if (!GetAclInformation(dacl, out var information, (uint)Marshal.SizeOf<AclSizeInformation>(), 2)) throw new Win32Exception(Marshal.GetLastPInvokeError());
                    if (information.AceCount == 0) return "empty DACL";
                    if (!GetAce(dacl, 0, out var ace)) throw new Win32Exception(Marshal.GetLastPInvokeError());

                    var mask = unchecked((uint)Marshal.ReadInt32(ace, 4));
                    var sid = ace + 8;
                    if (!ConvertSidToStringSid(sid, out var stringSid)) throw new Win32Exception(Marshal.GetLastPInvokeError());
                    try { return $"first ACE mask=0x{mask:X8}, SID={Marshal.PtrToStringUni(stringSid)}"; }
                    finally { _ = LocalFree(stringSid); }
                }
            }
        }
        finally
        {
            _ = RegCloseKey(key);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AclSizeInformation
    {
        internal uint AceCount;
        internal uint AclBytesInUse;
        internal uint AclBytesFree;
    }

    [LibraryImport("advapi32.dll", EntryPoint = "RegOpenKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegOpenKeyEx(nint root, string subKey, uint options, uint desiredAccess, out nint key);
    [LibraryImport("advapi32.dll", EntryPoint = "RegCloseKey")]
    private static partial int RegCloseKey(nint key);
    [LibraryImport("advapi32.dll", EntryPoint = "RegGetKeySecurity")]
    private static partial int RegGetKeySecurity(nint key, uint securityInformation, nint descriptor, ref uint descriptorLength);
    [LibraryImport("advapi32.dll", EntryPoint = "GetSecurityDescriptorDacl", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetSecurityDescriptorDacl(nint descriptor, [MarshalAs(UnmanagedType.Bool)] out bool present, out nint dacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [LibraryImport("advapi32.dll", EntryPoint = "GetAclInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetAclInformation(nint dacl, out AclSizeInformation information, uint informationLength, uint informationClass);
    [LibraryImport("advapi32.dll", EntryPoint = "GetAce", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetAce(nint dacl, uint aceIndex, out nint ace);
    [LibraryImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertSidToStringSid(nint sid, out nint stringSid);
    [LibraryImport("kernel32.dll", EntryPoint = "LocalFree")]
    private static partial nint LocalFree(nint memory);
}
