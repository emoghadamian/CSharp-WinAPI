namespace CSharp.WinAPI.Modules;

/// <summary>Read-only module information obtained from a Toolhelp32 module snapshot.</summary>
/// <param name="ModuleName">The module's filename.</param>
/// <param name="ModulePath">The module's fully qualified path as reported by MODULEENTRY32.</param>
/// <param name="BaseAddress">The module's unsigned pointer-sized base address in the owning process.</param>
/// <param name="ModuleSize">The module image size in bytes.</param>
/// <param name="ProcessId">The identifier of the process that owns the module.</param>
public sealed record ModuleInfo(
    string ModuleName,
    string ModulePath,
    nuint BaseAddress,
    uint ModuleSize,
    uint ProcessId);
