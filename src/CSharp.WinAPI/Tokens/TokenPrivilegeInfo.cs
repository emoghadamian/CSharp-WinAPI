namespace CSharp.WinAPI.Tokens;

/// <summary>Read-only token privilege metadata; the LUID remains available when its name cannot be resolved.</summary>
public sealed record TokenPrivilegeInfo(ulong Luid, string? Name, TokenPrivilegeAttributes Attributes)
{
    /// <summary>Gets whether the privilege is enabled in the token.</summary>
    public bool IsEnabled => Attributes.HasFlag(TokenPrivilegeAttributes.Enabled);

    /// <summary>Gets whether the privilege is enabled by default.</summary>
    public bool IsEnabledByDefault => Attributes.HasFlag(TokenPrivilegeAttributes.EnabledByDefault);

    /// <summary>Gets whether the privilege is marked removed.</summary>
    public bool IsRemoved => Attributes.HasFlag(TokenPrivilegeAttributes.Removed);

    /// <summary>Gets the unmodified native privilege-attribute value.</summary>
    public uint RawAttributes => (uint)Attributes;
}
