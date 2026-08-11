using CSharp.WinAPI.Registry;
using RegistrySecurityInspection;

var subKey = args.FirstOrDefault() ?? "Software";
var path = new RegistryKeyPath(RegistryHive.CurrentUser, subKey);
var info = new RegistrySecurityInspector().Inspect(path);

Console.WriteLine($"Key: HKCU\\{info.Path.SubKey} ({info.Path.View})");
Console.WriteLine($"Owner: {info.Owner?.Sid} ({info.Owner?.AccountName ?? "unresolved"})");
Console.WriteLine($"Group: {info.Group?.Sid ?? "not present"}");
Console.WriteLine($"DACL: present={info.Dacl.IsPresent}, null={info.Dacl.IsNull}, empty={info.Dacl.IsEmpty}");
Console.WriteLine($"Control: 0x{(ushort)info.ControlFlags:X4}; ACE count: {info.Dacl.Entries.Count}");
foreach (var ace in info.Dacl.Entries.Take(30))
{
    Console.WriteLine($"{ace.Type} raw={ace.RawType} sid={ace.Trustee?.Sid ?? "unsupported ACE layout"} mask={ace.AccessMask?.ToString("X8") ?? "n/a"} inherited={ace.IsInherited}");
}

Console.WriteLine($"Raw LibraryImport example: {RawRegistrySecurity.DescribeFirstAce(subKey)}");
