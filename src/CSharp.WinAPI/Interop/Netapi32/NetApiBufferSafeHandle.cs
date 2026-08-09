using Microsoft.Win32.SafeHandles;

namespace CSharp.WinAPI.Interop.Netapi32;

/// <summary>Owns a buffer allocated by a Netapi32 network-management API.</summary>
internal sealed class NetApiBufferSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal NetApiBufferSafeHandle(nint handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle() =>
        NetApiNative.NetApiBufferFree(handle) == NetApiNative.NerrSuccess;
}
