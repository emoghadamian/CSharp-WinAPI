using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Tdh;

internal static partial class EtwProviderNative
{
    [LibraryImport("tdh.dll", EntryPoint = "TdhEnumerateProviders")]
    internal static partial uint TdhEnumerateProviders(nint buffer, ref uint bufferSize);
}
