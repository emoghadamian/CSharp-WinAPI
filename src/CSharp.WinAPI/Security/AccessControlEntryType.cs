namespace CSharp.WinAPI.Security;

/// <summary>Recognized ACE forms in this read-only DACL inspector.</summary>
public enum AccessControlEntryType
{
    /// <summary>An ACE whose raw type is retained but not semantically interpreted.</summary>
    Unknown,
    /// <summary>An access-allowed ACE.</summary>
    Allowed,
    /// <summary>An access-denied ACE.</summary>
    Denied,
    /// <summary>A system-audit ACE.</summary>
    SystemAudit,
}
