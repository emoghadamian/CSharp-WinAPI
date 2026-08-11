namespace CSharp.WinAPI.Tokens;

/// <summary>Read-only access-token metadata associated with one process at inspection time.</summary>
public sealed record TokenInfo(
    uint ProcessId,
    TokenUserInfo User,
    IReadOnlyList<TokenGroupInfo> Groups,
    IReadOnlyList<TokenPrivilegeInfo> Privileges,
    bool IsElevated,
    TokenIntegrityLevelInfo IntegrityLevel,
    uint SessionId,
    TokenTypeInfo Type,
    TokenImpersonationLevelInfo? ImpersonationLevel)
{
    /// <summary>Gets an immutable snapshot of group SIDs and attributes.</summary>
    public IReadOnlyList<TokenGroupInfo> Groups { get; } = Array.AsReadOnly(Groups.ToArray());

    /// <summary>Gets an immutable snapshot of token privileges.</summary>
    public IReadOnlyList<TokenPrivilegeInfo> Privileges { get; } = Array.AsReadOnly(Privileges.ToArray());
}
