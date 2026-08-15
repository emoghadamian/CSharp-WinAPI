namespace CSharp.WinAPI.Events;
/// <summary>Immutable metadata and authoritative XML rendered for one Windows Event Log record.</summary>
public sealed record EventLogRecord(string? ProviderName, uint? EventId, byte? Version, byte? Level, ushort? Task, byte? Opcode, string? Keywords, ulong? RecordId, string? Channel, string? Computer, DateTimeOffset? TimeCreated, uint? ProcessId, uint? ThreadId, string? UserSid, IReadOnlyList<EventLogDataField> EventData, string Xml);
