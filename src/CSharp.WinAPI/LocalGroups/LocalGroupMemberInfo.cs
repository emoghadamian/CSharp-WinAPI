namespace CSharp.WinAPI.LocalGroups;

/// <summary>A member of a local security group reported by NetLocalGroupGetMembers.</summary>
/// <param name="AccountName">The resolved domain-qualified account name, when available.</param>
/// <param name="SidUsage">The Windows SID_NAME_USE value as a descriptive string.</param>
public sealed record LocalGroupMemberInfo(string? AccountName, string SidUsage);
