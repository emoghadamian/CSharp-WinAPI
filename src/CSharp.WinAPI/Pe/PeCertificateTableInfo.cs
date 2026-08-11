namespace CSharp.WinAPI.Pe;

/// <summary>Read-only PE Certificate Table metadata; its address is a file offset, not an RVA.</summary>
public sealed record PeCertificateTableInfo(uint FileOffset, uint Size, IReadOnlyList<PeCertificateInfo> Entries)
{
    /// <summary>Gets an immutable snapshot of WIN_CERTIFICATE entries.</summary>
    public IReadOnlyList<PeCertificateInfo> Entries { get; } = PeCollectionSnapshot.Create(Entries);

    /// <summary>Gets the number of WIN_CERTIFICATE entries.</summary>
    public int EntryCount => Entries.Count;
}
