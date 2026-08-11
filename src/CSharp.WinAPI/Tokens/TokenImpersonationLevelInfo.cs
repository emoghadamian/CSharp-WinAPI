namespace CSharp.WinAPI.Tokens;

/// <summary>Raw impersonation-level value and its recognized classification.</summary>
public sealed record TokenImpersonationLevelInfo(uint RawValue, TokenImpersonationLevel Value);
