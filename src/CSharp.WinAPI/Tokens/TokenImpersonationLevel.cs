namespace CSharp.WinAPI.Tokens;

/// <summary>Recognized security impersonation levels.</summary>
public enum TokenImpersonationLevel
{
    /// <summary>The native value is not recognized by this library version.</summary>
    Unknown = -1,
    /// <summary>The server cannot identify the client.</summary>
    Anonymous = 0,
    /// <summary>The server can identify but not impersonate the client.</summary>
    Identification = 1,
    /// <summary>The server can impersonate the client locally.</summary>
    Impersonation = 2,
    /// <summary>The server can impersonate the client across machines.</summary>
    Delegation = 3,
}
