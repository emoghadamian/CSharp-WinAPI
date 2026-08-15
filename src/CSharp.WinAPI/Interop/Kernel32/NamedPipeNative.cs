using System.Runtime.InteropServices;
namespace CSharp.WinAPI.Interop.Kernel32;
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
internal unsafe struct Win32FindDataNative
{
    internal uint Attributes;
    internal uint CreationLow;
    internal uint CreationHigh;
    internal uint AccessLow;
    internal uint AccessHigh;
    internal uint WriteLow;
    internal uint WriteHigh;
    internal uint SizeHigh;
    internal uint SizeLow;
    internal uint Reserved0;
    internal uint Reserved1;
    internal fixed char FileName[260];
    internal fixed char AlternateFileName[14];
}

internal static partial class NamedPipeNative
{
    [LibraryImport("kernel32.dll", EntryPoint = "FindFirstFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial nint FindFirstFile(string pattern, out Win32FindDataNative data);

    [LibraryImport("kernel32.dll", EntryPoint = "FindNextFileW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool FindNextFile(SafeNamedPipeSearchHandle search, out Win32FindDataNative data);

    [LibraryImport("kernel32.dll", EntryPoint = "FindClose", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool FindClose(nint search);
}
