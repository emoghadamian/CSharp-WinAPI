namespace CSharp.WinAPI.LocalGroups;

/// <summary>A local security group reported by NetLocalGroupEnum.</summary>
/// <param name="Name">The local group's Unicode name.</param>
public sealed record LocalGroupInfo(string Name);
