namespace CSharp.WinAPI.Threads;

/// <summary>Read-only thread information obtained from a Toolhelp32 snapshot.</summary>
/// <param name="ThreadId">The system-assigned thread identifier.</param>
/// <param name="ProcessId">The identifier of the owning process.</param>
/// <param name="BasePriority">The kernel base priority reported by THREADENTRY32.</param>
public sealed record ThreadInfo(uint ThreadId, uint ProcessId, int BasePriority);
