using Microsoft.Win32.SafeHandles;

namespace CSharp.WinAPI.Interop.Kernel32;

internal sealed class SafeNamedPipeSearchHandle : SafeHandleMinusOneIsInvalid
{
    internal SafeNamedPipeSearchHandle(nint value) : base(ownsHandle: true) => SetHandle(value);

    protected override bool ReleaseHandle() => NamedPipeNative.FindClose(handle);
}
