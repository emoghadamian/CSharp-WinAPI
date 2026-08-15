using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Wevtapi;

/// <summary>Owns a Windows Event Log handle and releases it with EvtClose.</summary>
internal sealed class SafeEventHandle : SafeHandle
{
    internal SafeEventHandle() : base(nint.Zero, ownsHandle: true) { }
    internal SafeEventHandle(nint value) : this() => SetHandle(value);
    /// <inheritdoc />
    public override bool IsInvalid => handle == nint.Zero;
    protected override bool ReleaseHandle() => EventLogNative.EvtClose(handle);
}
