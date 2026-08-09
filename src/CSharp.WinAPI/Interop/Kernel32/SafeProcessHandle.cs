using Microsoft.Win32.SafeHandles;

namespace CSharp.WinAPI.Interop.Kernel32;

/// <summary>Owns an opened process HANDLE and releases it with CloseHandle.</summary>
internal sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeProcessHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => Kernel32Native.CloseHandle(handle);
}
