using System.Runtime.InteropServices;
namespace CSharp.WinAPI.Interop.Ntdll;
internal static partial class NtdllNative
{
    [LibraryImport("ntdll.dll", EntryPoint = "NtQuerySystemInformation")]
    internal static partial int NtQuerySystemInformation(int informationClass, nint information, uint informationLength, out uint returnLength);
}
