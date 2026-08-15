using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Tdh;

internal sealed class PinnedBufferLease : IDisposable
{
    private GCHandle handle;

    internal PinnedBufferLease(byte[] buffer) => handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);

    internal nint Pointer
    {
        get
        {
            if (!handle.IsAllocated) throw new ObjectDisposedException(nameof(PinnedBufferLease));
            return handle.AddrOfPinnedObject();
        }
    }

    public void Dispose()
    {
        if (handle.IsAllocated) handle.Free();
    }
}
