namespace CSharp.WinAPI.Pe;

/// <summary>Read-only metadata for one IMAGE_IMPORT_DESCRIPTOR and its normal imported functions.</summary>
public sealed record PeImportModuleInfo(
    string Name,
    uint OriginalFirstThunk,
    uint FirstThunk,
    uint TimeDateStamp,
    uint ForwarderChain,
    IReadOnlyList<PeImportFunctionInfo> Functions);
