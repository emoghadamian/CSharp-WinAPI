using CSharp.WinAPI.Events;
using EventLogInspection;
var inspector = new EventLogInspector();
var channels = inspector.EnumerateChannels();
Console.WriteLine($"Channels returned: {channels.Count}");
foreach (var channel in channels.Take(12)) Console.WriteLine($"  {channel}");
var records = inspector.Query("System", "*", 5);
Console.WriteLine($"System events returned: {records.Count}");
foreach (var record in records) { Console.WriteLine($"{record.TimeCreated:O} {record.ProviderName ?? "<unknown>"} ID={record.EventId}"); Console.WriteLine(record.Xml.Length <= 600 ? record.Xml : $"{record.Xml[..600]}..."); }
Console.WriteLine($"Raw LibraryImport example: {RawEventLog.DescribeLatestSystemEvent()}");
