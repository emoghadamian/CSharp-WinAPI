using Microsoft.Win32.SafeHandles;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Interop.Advapi32;

/// <summary>Owns a LocalAlloc security-descriptor buffer returned by GetNamedSecurityInfo.</summary>
internal sealed class SafeSecurityDescriptorHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeSecurityDescriptorHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => Kernel32Native.LocalFree(handle) == nint.Zero;
}
