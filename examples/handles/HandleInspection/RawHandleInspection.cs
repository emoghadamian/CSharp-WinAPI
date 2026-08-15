using System.Runtime.InteropServices;
namespace HandleInspection;
internal static partial class RawHandleInspection
{
    internal static unsafe string Describe() { var length=64*1024; while(true){var buffer=Marshal.AllocHGlobal(length);try{var status=NtQuerySystemInformation(64,buffer,(uint)length,out var needed);if(status==0){var count=IntPtr.Size==8?*(ulong*)buffer:*(uint*)buffer;return $"{count} entries from SystemExtendedHandleInformation";}if(status!=unchecked((int)0xC0000004)||needed<=length||needed>64*1024*1024)throw new InvalidOperationException($"NtQuerySystemInformation NTSTATUS 0x{status:X8}");length=checked((int)needed);}finally{Marshal.FreeHGlobal(buffer);}} }
    [LibraryImport("ntdll.dll",EntryPoint="NtQuerySystemInformation")] private static partial int NtQuerySystemInformation(int informationClass,nint information,uint length,out uint returnLength);
}
