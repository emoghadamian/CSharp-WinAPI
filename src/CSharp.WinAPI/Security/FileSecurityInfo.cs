namespace CSharp.WinAPI.Security;

/// <summary>Read-only security-descriptor metadata for a file-system object.</summary>
public sealed record FileSecurityInfo(
    string Path,
    SecurityIdentifierInfo? Owner,
    SecurityIdentifierInfo? Group,
    DiscretionaryAclInfo Dacl,
    SecurityDescriptorControlFlags ControlFlags,
    ushort ControlRevision)
{
    /// <summary>Gets the unmodified native security-descriptor control value.</summary>
    public ushort RawControlFlags => (ushort)ControlFlags;
}
