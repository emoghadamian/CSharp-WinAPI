namespace CSharp.WinAPI.Pe;

/// <summary>Read-only metadata from one optional-header data-directory entry.</summary>
public sealed record PeDataDirectoryInfo(PeDataDirectoryKind Kind, uint Address, uint Size, bool AddressIsFileOffset)
{
    /// <summary>Gets whether this directory has a nonzero address and size.</summary>
    public bool IsPresent => Address != 0 && Size != 0;
}
