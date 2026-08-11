using System.ComponentModel;
using System.Runtime.InteropServices;
namespace AccessCheckExample;
internal static partial class RawAccessCheck
{
    [StructLayout(LayoutKind.Sequential)] private struct GenericMapping { internal uint Read, Write, Execute, All; }
    internal static unsafe string Evaluate(string path, uint desired)
    {
        var status = GetNamedSecurityInfo(path, 1, 7, out _, out _, out _, nint.Zero, out var descriptor); if (status != 0) throw new Win32Exception((int)status);
        if (!OpenProcessToken(GetCurrentProcess(), 0xA, out var primary)) { _ = LocalFree(descriptor); throw new Win32Exception(Marshal.GetLastPInvokeError()); }
        try { if (!DuplicateToken(primary, 2, out var client)) throw new Win32Exception(Marshal.GetLastPInvokeError()); try { var mapping = new GenericMapping { Read = 0x00120089, Write = 0x00120116, Execute = 0x001200A0, All = 0x001F01FF }; MapGenericMask(ref desired, in mapping); var privileges = Marshal.AllocHGlobal(1024); try { uint length=1024; if (!AccessCheck(descriptor, client, desired, in mapping, privileges, ref length, out var granted, out var allowed)) throw new Win32Exception(Marshal.GetLastPInvokeError()); return $"desired=0x{desired:X8}, granted=0x{granted:X8}, allowed={allowed}"; } finally { Marshal.FreeHGlobal(privileges); } } finally { _=CloseHandle(client); } } finally { _=CloseHandle(primary); _=LocalFree(descriptor); }
    }
    [LibraryImport("kernel32.dll", EntryPoint="GetCurrentProcess")] private static partial nint GetCurrentProcess();
    [LibraryImport("advapi32.dll", EntryPoint="GetNamedSecurityInfoW", StringMarshalling=StringMarshalling.Utf16)] private static partial uint GetNamedSecurityInfo(string path,int type,uint info,out nint o,out nint g,out nint d,nint s,out nint sd);
    [LibraryImport("advapi32.dll", EntryPoint="OpenProcessToken",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)] private static partial bool OpenProcessToken(nint p,uint access,out nint t);
    [LibraryImport("advapi32.dll", EntryPoint="DuplicateToken",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)] private static partial bool DuplicateToken(nint t,int level,out nint copy);
    [LibraryImport("advapi32.dll", EntryPoint="MapGenericMask")] private static partial void MapGenericMask(ref uint mask,in GenericMapping mapping);
    [LibraryImport("advapi32.dll", EntryPoint="AccessCheck",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)] private static partial bool AccessCheck(nint sd,nint token,uint desired,in GenericMapping mapping,nint privileges,ref uint length,out uint granted,[MarshalAs(UnmanagedType.Bool)]out bool allowed);
    [LibraryImport("kernel32.dll",EntryPoint="CloseHandle")][return:MarshalAs(UnmanagedType.Bool)] private static partial bool CloseHandle(nint h);
    [LibraryImport("kernel32.dll",EntryPoint="LocalFree")] private static partial nint LocalFree(nint p);
}
