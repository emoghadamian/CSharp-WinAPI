namespace CSharp.WinAPI.Tokens;

/// <summary>Raw token-type value and its recognized classification.</summary>
public sealed record TokenTypeInfo(uint RawValue, TokenType Value);
