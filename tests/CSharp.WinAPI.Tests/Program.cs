using CSharp.WinAPI.LocalGroups;
using CSharp.WinAPI.Processes;

var failures = new List<string>();
var inspector = new LocalGroupInspector();

Run("local-group enumeration returns named groups", () =>
{
    var groups = inspector.EnumerateLocalGroups();
    Assert(groups.Count > 0, "No local groups were returned.");
    Assert(groups.All(group => !string.IsNullOrWhiteSpace(group.Name)), "A group had no name.");
});

Run("members can be read for an enumerated group", () =>
{
    var group = inspector.EnumerateLocalGroups().First();
    var members = inspector.EnumerateMembers(group.Name);
    Assert(members.All(member => !string.IsNullOrWhiteSpace(member.SidUsage)), "A member had no SID usage.");
});

Run("an invalid local group preserves the native error", () =>
{
    const string missingGroup = "CSharpWinApi-Definitely-Not-A-Local-Group";

    try
    {
        _ = inspector.EnumerateMembers(missingGroup);
        throw new InvalidOperationException("The API unexpectedly found the deliberately invalid group.");
    }
    catch (NetApiException exception)
    {
        Assert(
            exception.NativeErrorCode is 1376 or 2220,
            $"Expected ERROR_NO_SUCH_ALIAS (1376) or NERR_GroupNotFound (2220), got {exception.NativeErrorCode}.");
    }
});

var processInspector = new ProcessInspector();

Run("process enumeration contains the current process", () =>
{
    var processes = processInspector.EnumerateProcesses();
    Assert(processes.Any(process => process.ProcessId == (uint)Environment.ProcessId), "The current process was absent from the snapshot.");
});

Run("current process has core inspection data", () =>
{
    var process = processInspector.InspectProcess((uint)Environment.ProcessId);
    Assert(process.ProcessId == (uint)Environment.ProcessId, "The inspected PID did not match the current process.");
    Assert(!string.IsNullOrWhiteSpace(process.Name), "The current process had no executable name.");
    Assert(!string.IsNullOrWhiteSpace(process.ExecutablePath), "The current process had no executable path.");
    Assert(process.CreationTimeUtc is not null, "The current process had no creation time.");
    Assert(process.SessionId is not null, "The current process had no session ID.");
    Assert(process.Architecture is not null, "The current process architecture was unavailable.");
});

Run("invalid process IDs are reported", () =>
{
    try
    {
        _ = processInspector.InspectProcess(uint.MaxValue);
        throw new InvalidOperationException("The impossible PID was unexpectedly present in the snapshot.");
    }
    catch (ProcessInspectionException exception)
    {
        Assert(exception.NativeErrorCode == 1168, $"Expected ERROR_NOT_FOUND (1168), got {exception.NativeErrorCode}.");
    }
});

Run("process inspection can be repeated without retaining handles", () =>
{
    for (var iteration = 0; iteration < 3; iteration++)
    {
        var processes = processInspector.EnumerateProcesses();
        Assert(processes.Count > 0, "Process enumeration returned no entries.");
    }
});

return failures.Count == 0 ? 0 : 1;

void Run(string name, Action test)
{
    try
    {
        test();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception exception)
    {
        failures.Add(name);
        Console.Error.WriteLine($"FAIL {name}: {exception.Message}");
    }
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
