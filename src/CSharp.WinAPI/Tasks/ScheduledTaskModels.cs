#pragma warning disable CS1591
namespace CSharp.WinAPI.Tasks;

public enum ScheduledTaskState { Unknown, Disabled, Queued, Ready, Running }
public sealed record ScheduledTaskStateInfo(int RawValue, ScheduledTaskState Value);
public sealed record ScheduledTaskRegistrationInfo(string? Author, string? Description, string? Source, string? Version, string? Date);
public sealed record ScheduledTaskPrincipalInfo(string? UserId, string? GroupId, int RawLogonType, int RawRunLevel);
public sealed record ScheduledTaskSettingsInfo(bool Enabled, bool Hidden, bool AllowDemandStart, bool StartWhenAvailable, int Priority, string? ExecutionTimeLimit);
public sealed record ScheduledTaskTriggerInfo(int RawType, bool Enabled, string? StartBoundary, string? EndBoundary, string? RepetitionInterval, string? RepetitionDuration);
public sealed record ScheduledTaskActionInfo(int RawType, string? Path, string? Arguments, string? WorkingDirectory, string? ClassId);
public sealed record ScheduledTaskInfo(string Path, string Name, string FolderPath, ScheduledTaskStateInfo State, bool Enabled, ScheduledTaskRegistrationInfo Registration, ScheduledTaskPrincipalInfo Principal, ScheduledTaskSettingsInfo Settings, IReadOnlyList<ScheduledTaskTriggerInfo> Triggers, IReadOnlyList<ScheduledTaskActionInfo> Actions);
#pragma warning restore CS1591
