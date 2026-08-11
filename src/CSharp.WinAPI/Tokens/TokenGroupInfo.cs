namespace CSharp.WinAPI.Tokens;

/// <summary>Read-only token group SID and unmodified native attribute flags.</summary>
public sealed record TokenGroupInfo(string Sid, TokenGroupAttributes Attributes)
{
    /// <summary>Gets the unmodified native group-attribute value.</summary>
    public uint RawAttributes => (uint)Attributes;
}
