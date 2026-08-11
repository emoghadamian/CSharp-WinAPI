namespace CSharp.WinAPI.Tokens;

/// <summary>Documented SID-and-attributes flags reported for a token group.</summary>
[Flags]
public enum TokenGroupAttributes : uint
{
    /// <summary>The group is mandatory.</summary>
    Mandatory = 0x00000001,
    /// <summary>The group is enabled by default.</summary>
    EnabledByDefault = 0x00000002,
    /// <summary>The group is currently enabled.</summary>
    Enabled = 0x00000004,
    /// <summary>The group identifies the token owner.</summary>
    Owner = 0x00000008,
    /// <summary>The group is present only for deny checks.</summary>
    UseForDenyOnly = 0x00000010,
    /// <summary>The group is an integrity SID.</summary>
    Integrity = 0x00000020,
    /// <summary>The integrity SID is enabled.</summary>
    IntegrityEnabled = 0x00000040,
    /// <summary>The group is resource-specific.</summary>
    Resource = 0x20000000,
    /// <summary>The group represents a logon session.</summary>
    LogonId = 0xC0000000,
}
