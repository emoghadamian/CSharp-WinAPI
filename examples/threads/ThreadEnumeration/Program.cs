using CSharp.WinAPI.Threads;
using ThreadEnumeration;

// Toolhelp32 flow: CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) -> THREADENTRY32 -> Thread32First/Next -> ThreadInfo.
// Snapshot enumeration does not need opened thread handles, so it remains read-only and works for normal users.
var inspector = new ThreadInspector();
var allThreads = inspector.EnumerateThreads();
var currentProcessId = (uint)Environment.ProcessId;
var currentProcessThreads = inspector.EnumerateProcessThreads(currentProcessId);

Console.WriteLine($"Visible threads: {allThreads.Count}");
Console.WriteLine($"Threads owned by current process ({currentProcessId}): {currentProcessThreads.Count}");
Console.WriteLine("Thread ID   Owner PID   Base priority");

foreach (var thread in currentProcessThreads.OrderBy(thread => thread.ThreadId))
{
    Console.WriteLine($"{thread.ThreadId,-11} {thread.ProcessId,-11} {thread.BasePriority}");
}

var raw = RawThreadSnapshot.ReadFirstThread();
Console.WriteLine();
Console.WriteLine($"Raw LibraryImport THREADENTRY32 example: TID {raw.ThreadId}, owner PID {raw.ProcessId}, base priority {raw.BasePriority}");
