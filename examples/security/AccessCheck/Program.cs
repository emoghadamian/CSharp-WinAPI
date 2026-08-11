using CSharp.WinAPI.Security;
using AccessCheckExample;
var path = args.FirstOrDefault() ?? Environment.ProcessPath!;
var desired = 0x80000000u; // GENERIC_READ
var result = new AccessCheckInspector().EvaluatePathAccess(path, desired);
Console.WriteLine($"Path: {path}\nDesired: 0x{result.DesiredAccess:X8}\nMapped desired: 0x{result.MappedDesiredAccess:X8}\nGranted: 0x{result.GrantedAccess:X8}\nGranted?: {result.IsGranted}\nPrivileges reported: {result.PrivilegesUsed.Count}");
Console.WriteLine("Access denied is a valid authorization result, not necessarily an API failure.");
Console.WriteLine($"Raw LibraryImport example: {RawAccessCheck.Evaluate(path, desired)}");
