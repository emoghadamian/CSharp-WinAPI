using CSharp.WinAPI.LocalGroups;

var inspector = new LocalGroupInspector();

foreach (var group in inspector.EnumerateLocalGroups().OrderBy(group => group.Name, StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine(group.Name);

    foreach (var member in inspector.EnumerateMembers(group.Name))
    {
        Console.WriteLine($"  {member.AccountName ?? "<unresolved>"} ({member.SidUsage})");
    }
}
