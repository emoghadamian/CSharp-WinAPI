namespace CSharp.WinAPI.Tokens;

/// <summary>Mandatory integrity SID, RID, and normalized classification.</summary>
public sealed record TokenIntegrityLevelInfo(string Sid, uint Rid, TokenIntegrityLevel Level);
