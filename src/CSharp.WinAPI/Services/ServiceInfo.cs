namespace CSharp.WinAPI.Services;

/// <summary>Read-only runtime status metadata returned by EnumServicesStatusExW.</summary>
public sealed record ServiceInfo(
    string Name,
    string DisplayName,
    ServiceTypeInfo Type,
    ServiceStateInfo State,
    uint RawAcceptedControls,
    uint Win32ExitCode,
    uint ServiceSpecificExitCode,
    uint CheckPoint,
    uint WaitHint,
    uint ProcessId,
    uint ServiceFlags)
{
    /// <summary>Gets known accepted-control flags while retaining unknown bits in <see cref="RawAcceptedControls"/>.</summary>
    public ServiceAcceptedControls AcceptedControls => (ServiceAcceptedControls)RawAcceptedControls;
}
