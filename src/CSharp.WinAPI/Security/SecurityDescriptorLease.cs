using CSharp.WinAPI.Interop.Advapi32;

namespace CSharp.WinAPI.Security;

/// <summary>Internal lifetime scope for a native file security descriptor.</summary>
internal sealed class SecurityDescriptorLease : IDisposable
{
    private SecurityDescriptorLease(string path, SafeSecurityDescriptorHandle descriptor) { Path = path; Descriptor = descriptor; }
    internal string Path { get; }
    internal SafeSecurityDescriptorHandle Descriptor { get; }
    internal nint Pointer => Descriptor.DangerousGetHandle();

    internal static SecurityDescriptorLease Open(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var target = System.IO.Path.GetFullPath(path);
        var status = Advapi32Native.GetNamedSecurityInfo(target, SecurityObjectType.FileObject, SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl, out _, out _, out _, nint.Zero, out var descriptor);
        if (status != 0) { descriptor.Dispose(); throw new FileSecurityInspectionException(nameof(Advapi32Native.GetNamedSecurityInfo), target, unchecked((int)status)); }
        return new SecurityDescriptorLease(target, descriptor);
    }

    public void Dispose() => Descriptor.Dispose();
}
