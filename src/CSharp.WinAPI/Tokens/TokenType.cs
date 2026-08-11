namespace CSharp.WinAPI.Tokens;

/// <summary>Recognized Windows access-token types.</summary>
public enum TokenType
{
    /// <summary>The native value is not recognized by this library version.</summary>
    Unknown,
    /// <summary>A primary process token.</summary>
    Primary,
    /// <summary>An impersonation token.</summary>
    Impersonation,
}
