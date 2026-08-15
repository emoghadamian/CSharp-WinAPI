using CSharp.WinAPI.Handles;
using HandleInspection;
var inspector = new HandleInspector(); var result = inspector.Inspect();
Console.WriteLine($"System handles: {result.Handles.Count}");
foreach (var group in result.Handles.GroupBy(handle => handle.ProcessId).OrderByDescending(group => group.Count()).Take(12)) Console.WriteLine($"PID {group.Key}: {group.Count()} handles");
foreach (var handle in HandleInspector.FilterByProcess(result, (uint)Environment.ProcessId).Take(10)) Console.WriteLine($"current: value=0x{handle.HandleValue:X}, type={handle.ObjectTypeIndex}, access=0x{handle.GrantedAccess:X8}");
Console.WriteLine($"Raw NT example: {RawHandleInspection.Describe()}");
