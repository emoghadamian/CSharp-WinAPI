using Microsoft.Win32.SafeHandles;

namespace CSharp.WinAPI.Interop.Kernel32;

/// <summary>Owns a Toolhelp snapshot HANDLE and releases it with CloseHandle.</summary>
internal sealed class SafeSnapshotHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeSnapshotHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => Kernel32Native.CloseHandle(handle);
}
