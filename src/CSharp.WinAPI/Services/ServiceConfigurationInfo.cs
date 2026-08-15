namespace CSharp.WinAPI.Services;

/// <summary>Read-only configuration metadata returned by QueryServiceConfigW.</summary>
public sealed record ServiceConfigurationInfo(
    string ServiceName,
    string? DisplayName,
    ServiceTypeInfo Type,
    ServiceStartTypeInfo StartType,
    ServiceErrorControlInfo ErrorControl,
    string? BinaryPath,
    string? LoadOrderGroup,
    uint? TagId,
    IReadOnlyList<ServiceDependencyInfo> Dependencies,
    string? ServiceStartName);
