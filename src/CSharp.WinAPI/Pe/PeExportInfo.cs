namespace CSharp.WinAPI.Pe;

/// <summary>Read-only metadata from IMAGE_EXPORT_DIRECTORY and its associated export tables.</summary>
public sealed record PeExportInfo(
    uint Characteristics,
    uint TimeDateStamp,
    ushort MajorVersion,
    ushort MinorVersion,
    string Name,
    uint OrdinalBase,
    uint NumberOfFunctions,
    uint NumberOfNames,
    uint AddressOfFunctions,
    uint AddressOfNames,
    uint AddressOfNameOrdinals,
    IReadOnlyList<PeExportFunctionInfo> Functions)
{
    /// <summary>Gets an immutable snapshot of export-address-table entries.</summary>
    public IReadOnlyList<PeExportFunctionInfo> Functions { get; } = PeCollectionSnapshot.Create(Functions);
}
