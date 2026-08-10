namespace CSharp.WinAPI.Pe;

/// <summary>Read-only metadata from one IMAGE_SECTION_HEADER.</summary>
public sealed record PeSectionInfo(
    string Name,
    uint VirtualSize,
    uint VirtualAddress,
    uint SizeOfRawData,
    uint PointerToRawData,
    uint PointerToRelocations,
    uint PointerToLinenumbers,
    ushort NumberOfRelocations,
    ushort NumberOfLinenumbers,
    PeSectionCharacteristics Characteristics)
{
    /// <summary>Gets the unmodified IMAGE_SECTION_HEADER characteristics value.</summary>
    public uint RawCharacteristics => (uint)Characteristics;
}
