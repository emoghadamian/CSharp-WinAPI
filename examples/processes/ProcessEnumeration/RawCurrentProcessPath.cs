using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ProcessEnumeration;

/// <summary>Minimal raw LibraryImport example; the core library uses a SafeHandle for opened process handles.</summary>
internal static unsafe partial class RawCurrentProcessPath
{
    private const int MaximumExtendedPathLength = 32768;

    internal static string Get()
    {
        var buffer = new char[MaximumExtendedPathLength];

        fixed (char* path = buffer)
        {
            var length = (uint)buffer.Length;

            if (!QueryFullProcessImageName(GetCurrentProcess(), flags: 0, path, ref length))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            return new string(buffer, 0, checked((int)length));
        }
    }

    // Native: HANDLE GetCurrentProcess(void). This is a pseudo-handle and must not be closed.
    [LibraryImport("kernel32.dll", EntryPoint = "GetCurrentProcess")]
    private static partial IntPtr GetCurrentProcess();

    // Native: BOOL QueryFullProcessImageNameW(HANDLE, DWORD, LPWSTR, PDWORD).
    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageName(IntPtr process, uint flags, char* path, ref uint length);
}
