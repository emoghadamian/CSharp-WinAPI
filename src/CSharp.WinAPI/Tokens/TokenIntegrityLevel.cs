namespace CSharp.WinAPI.Tokens;

/// <summary>Recognized mandatory integrity classifications.</summary>
public enum TokenIntegrityLevel
{
    /// <summary>The integrity RID is not recognized by this library version.</summary>
    Unknown,
    /// <summary>Untrusted integrity level.</summary>
    Untrusted,
    /// <summary>Low integrity level.</summary>
    Low,
    /// <summary>Medium integrity level.</summary>
    Medium,
    /// <summary>Medium-plus integrity level.</summary>
    MediumPlus,
    /// <summary>High integrity level.</summary>
    High,
    /// <summary>System integrity level.</summary>
    System,
    /// <summary>Protected-process integrity level.</summary>
    Protected,
}
