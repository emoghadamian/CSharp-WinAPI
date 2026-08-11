namespace CSharp.WinAPI.Security;

/// <summary>Distinguishes absent, null, empty, and populated DACL states.</summary>
public sealed record DiscretionaryAclInfo(bool IsPresent, bool IsNull, bool IsEmpty, IReadOnlyList<AccessControlEntryInfo> Entries)
{
    /// <summary>Gets an immutable snapshot of ACEs.</summary>
    public IReadOnlyList<AccessControlEntryInfo> Entries { get; } = Array.AsReadOnly(Entries.ToArray());
}
