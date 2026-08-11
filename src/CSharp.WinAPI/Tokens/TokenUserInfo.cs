namespace CSharp.WinAPI.Tokens;

/// <summary>The authoritative user SID from an access token and its optional resolved account name.</summary>
public sealed record TokenUserInfo(string Sid, string? AccountName);
