using System.Runtime.InteropServices;

// Native signature: DWORD GetCurrentProcessId();
// LibraryImport generates the P/Invoke stub at compile time for modern .NET.
Console.WriteLine($"Current process ID: {NativeMethods.GetCurrentProcessId()}");

internal static partial class NativeMethods
{
    [LibraryImport("kernel32.dll", EntryPoint = "GetCurrentProcessId")]
    internal static partial uint GetCurrentProcessId();
}
