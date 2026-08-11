using Microsoft.Win32.SafeHandles;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Interop.Advapi32;

/// <summary>Owns an access-token HANDLE and releases it with CloseHandle.</summary>
internal sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeTokenHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => Kernel32Native.CloseHandle(handle);
}
