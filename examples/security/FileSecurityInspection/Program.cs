using CSharp.WinAPI.Security;
var path = args.FirstOrDefault() ?? Environment.ProcessPath!;
var info = new FileSecurityInspector().Inspect(path);
Console.WriteLine($"Path: {info.Path}\nOwner: {info.Owner?.Sid} ({info.Owner?.AccountName ?? "unresolved"})\nGroup: {info.Group?.Sid}\nDACL: present={info.Dacl.IsPresent}, null={info.Dacl.IsNull}, empty={info.Dacl.IsEmpty}\nControl: 0x{info.RawControlFlags:X4}\nACE count: {info.Dacl.Entries.Count}");
foreach (var ace in info.Dacl.Entries.Take(30)) Console.WriteLine($"{ace.Type} raw={ace.RawType} sid={ace.Trustee?.Sid ?? "unsupported ACE layout"} mask={ace.AccessMask?.ToString("X8") ?? "n/a"} inherited={ace.IsInherited}");
