namespace CSharp.WinAPI.Security;

/// <summary>An authoritative SID string with an optional resolved account name.</summary>
public sealed record SecurityIdentifierInfo(string Sid, string? AccountName);
