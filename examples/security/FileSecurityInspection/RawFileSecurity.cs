using System.ComponentModel;
using System.Runtime.InteropServices;

namespace FileSecurityInspection;

// A deliberately small view of the native descriptor lifetime hidden by FileSecurityInspector.
internal static partial class RawFileSecurity
{
    private const uint OwnerSecurityInformation = 0x1;
    private const uint GroupSecurityInformation = 0x2;
    private const uint DaclSecurityInformation = 0x4;
    private const int FileObject = 1;

    internal static string DescribeFirstAce(string path)
    {
        var status = GetNamedSecurityInfo(path, FileObject, OwnerSecurityInformation | GroupSecurityInformation | DaclSecurityInformation, out _, out _, out _, nint.Zero, out var descriptor);
        if (status != 0) throw new Win32Exception(unchecked((int)status));
        try
        {
            if (!GetSecurityDescriptorDacl(descriptor, out var present, out var dacl, out _)) throw new Win32Exception(Marshal.GetLastPInvokeError());
            if (!present || dacl == nint.Zero) return present ? "NULL DACL" : "absent DACL";
            if (!GetAce(dacl, 0, out var ace)) throw new Win32Exception(Marshal.GetLastPInvokeError());
            var mask = unchecked((uint)Marshal.ReadInt32(ace, 4));
            var sid = ace + 8;
            if (!ConvertSidToStringSid(sid, out var stringSid)) throw new Win32Exception(Marshal.GetLastPInvokeError());
            try { return $"first ACE mask=0x{mask:X8}, SID={Marshal.PtrToStringUni(stringSid)}"; }
            finally { _ = LocalFree(stringSid); }
        }
        finally { _ = LocalFree(descriptor); }
    }

    [LibraryImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetNamedSecurityInfo(string path, int objectType, uint securityInformation, out nint owner, out nint group, out nint dacl, nint sacl, out nint descriptor);
    [LibraryImport("advapi32.dll", EntryPoint = "GetSecurityDescriptorDacl", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetSecurityDescriptorDacl(nint descriptor, [MarshalAs(UnmanagedType.Bool)] out bool present, out nint dacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [LibraryImport("advapi32.dll", EntryPoint = "GetAce", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetAce(nint dacl, uint index, out nint ace);
    [LibraryImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertSidToStringSid(nint sid, out nint stringSid);
    [LibraryImport("kernel32.dll", EntryPoint = "LocalFree")] private static partial nint LocalFree(nint memory);
}
