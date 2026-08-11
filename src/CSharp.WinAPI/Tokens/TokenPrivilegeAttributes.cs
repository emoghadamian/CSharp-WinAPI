namespace CSharp.WinAPI.Tokens;

/// <summary>Documented privilege attribute flags reported by TOKEN_PRIVILEGES.</summary>
[Flags]
public enum TokenPrivilegeAttributes : uint
{
    /// <summary>The privilege is disabled.</summary>
    Disabled = 0,
    /// <summary>The privilege is enabled by default.</summary>
    EnabledByDefault = 0x00000001,
    /// <summary>The privilege is currently enabled.</summary>
    Enabled = 0x00000002,
    /// <summary>The privilege was removed from the token.</summary>
    Removed = 0x00000004,
    /// <summary>The privilege was used for an access check.</summary>
    UsedForAccess = 0x80000000,
}
