using CSharp.WinAPI.Security;
namespace CSharp.WinAPI.Registry;

/// <summary>Read-only security metadata for a local registry key.</summary>
public sealed record RegistrySecurityInfo(
    RegistryKeyPath Path,
    SecurityIdentifierInfo? Owner,
    SecurityIdentifierInfo? Group,
    DiscretionaryAclInfo Dacl,
    SecurityDescriptorControlFlags ControlFlags,
    ushort ControlRevision);
