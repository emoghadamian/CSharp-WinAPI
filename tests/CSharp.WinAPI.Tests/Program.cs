using CSharp.WinAPI.LocalGroups;

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
