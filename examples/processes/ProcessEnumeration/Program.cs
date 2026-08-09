using CSharp.WinAPI.Processes;
using ProcessEnumeration;

// Managed abstraction: Toolhelp32 provides PID, parent PID, and executable name;
// query-limited process handles add path, creation time, session, and architecture when permitted.
var inspector = new ProcessInspector();

Console.WriteLine("PID     PPID    Session  Architecture  Name                         Image path");

foreach (var process in inspector.EnumerateProcesses().OrderBy(process => process.ProcessId))
{
    Console.WriteLine(
        $"{process.ProcessId,-7} {process.ParentProcessId,-7} " +
        $"{process.SessionId?.ToString() ?? "<denied>",-8} " +
        $"{process.Architecture?.ProcessArchitecture.ToString() ?? "<denied>",-13} " +
        $"{process.Name,-28} {process.ExecutablePath ?? "<access denied or unavailable>"}");
}

Console.WriteLine();
Console.WriteLine($"Raw LibraryImport example (QueryFullProcessImageNameW): {RawCurrentProcessPath.Get()}");
