namespace CSharp.WinAPI.Pe;

/// <summary>Read-only metadata for one entry in the export address table.</summary>
public sealed record PeExportFunctionInfo(
    string? Name,
    uint Ordinal,
    uint? AddressRva,
    bool IsNamed,
    bool IsForwarded,
    string? ForwarderName);
