namespace CSharp.WinAPI.Processes;

/// <summary>Read-only process information obtained from Toolhelp and Kernel32 APIs.</summary>
public sealed record ProcessInfo(
    uint ProcessId,
    uint ParentProcessId,
    string Name,
    string? ExecutablePath,
    DateTimeOffset? CreationTimeUtc,
    uint? SessionId,
    ProcessArchitectureInfo? Architecture,
    int? InspectionErrorCode)
{
    /// <summary>Whether every requested extended query completed without a Win32 error.</summary>
    public bool HasCompleteExtendedInformation => InspectionErrorCode is null;
}
