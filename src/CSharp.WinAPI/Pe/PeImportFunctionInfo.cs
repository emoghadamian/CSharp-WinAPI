namespace CSharp.WinAPI.Pe;

/// <summary>Read-only metadata for one normal import resolved from an import lookup table or IAT.</summary>
public sealed record PeImportFunctionInfo(
    string? Name,
    ushort? Ordinal,
    bool IsOrdinal,
    ushort? Hint,
    uint LookupTableRva,
    uint ImportAddressTableRva);
