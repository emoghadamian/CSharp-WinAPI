using Microsoft.Win32.SafeHandles;

namespace CSharp.WinAPI.Interop.Advapi32;

/// <summary>Owns an SCM or service handle and releases it with CloseServiceHandle.</summary>
internal sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeServiceHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => ServiceNative.CloseServiceHandle(handle);
}
