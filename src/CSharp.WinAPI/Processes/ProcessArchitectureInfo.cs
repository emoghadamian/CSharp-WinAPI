namespace CSharp.WinAPI.Processes;

/// <summary>Architecture information returned by IsWow64Process2 or its compatibility fallback.</summary>
/// <param name="ProcessArchitecture">Architecture of the inspected process.</param>
/// <param name="NativeArchitecture">Native architecture of the operating system.</param>
/// <param name="IsWow64">Whether the process is running under WOW64.</param>
public sealed record ProcessArchitectureInfo(
    ProcessArchitecture ProcessArchitecture,
    ProcessArchitecture NativeArchitecture,
    bool IsWow64);
