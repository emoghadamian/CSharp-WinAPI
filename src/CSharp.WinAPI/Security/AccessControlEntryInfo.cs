namespace CSharp.WinAPI.Security;

/// <summary>Read-only metadata from one DACL ACE; unsupported ACE layouts retain their raw type and flags.</summary>
public sealed record AccessControlEntryInfo(
    byte RawType,
    AccessControlEntryType Type,
    AccessControlEntryFlags Flags,
    uint? AccessMask,
    SecurityIdentifierInfo? Trustee)
{
    /// <summary>Gets whether Windows marked this ACE as inherited.</summary>
    public bool IsInherited => Flags.HasFlag(AccessControlEntryFlags.Inherited);

    /// <summary>Gets the unmodified native ACE-flags value.</summary>
    public byte RawFlags => (byte)Flags;
}
