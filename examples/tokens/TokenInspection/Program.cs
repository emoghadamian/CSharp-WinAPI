using CSharp.WinAPI.Tokens;
using TokenInspection;

var inspector = new TokenInspector();

try
{
    var token = inspector.InspectCurrentProcessToken();
    Console.WriteLine($"Access token for PID {token.ProcessId}");
    Console.WriteLine($"User SID: {token.User.Sid}");
    Console.WriteLine($"Account: {token.User.AccountName ?? "<not resolved>"}");
    Console.WriteLine($"Elevated: {token.IsElevated}");
    Console.WriteLine($"Integrity: {token.IntegrityLevel.Level} (RID 0x{token.IntegrityLevel.Rid:X}, {token.IntegrityLevel.Sid})");
    Console.WriteLine($"Session: {token.SessionId}");
    Console.WriteLine($"Type: {token.Type.Value} (raw {token.Type.RawValue})");
    Console.WriteLine($"Impersonation level: {token.ImpersonationLevel?.Value.ToString() ?? "<not applicable to primary token>"}");

    Console.WriteLine();
    Console.WriteLine($"Groups ({token.Groups.Count}):");
    foreach (var group in token.Groups.Take(20))
    {
        Console.WriteLine($"  {group.Sid}  [{group.Attributes}]");
    }

    if (token.Groups.Count > 20)
    {
        Console.WriteLine($"  ... {token.Groups.Count - 20} additional groups not displayed.");
    }

    Console.WriteLine();
    Console.WriteLine($"Privileges ({token.Privileges.Count}):");
    foreach (var privilege in token.Privileges.Take(20))
    {
        Console.WriteLine($"  {privilege.Name ?? "<unresolved>"} (LUID 0x{privilege.Luid:X}) [{privilege.Attributes}]");
    }

    if (token.Privileges.Count > 20)
    {
        Console.WriteLine($"  ... {token.Privileges.Count - 20} additional privileges not displayed.");
    }

    Console.WriteLine();
    Console.WriteLine($"Raw LibraryImport TOKEN_USER example: {RawTokenUser.GetCurrentUserSid()}");
}
catch (TokenInspectionException exception)
{
    Console.Error.WriteLine($"Token inspection failed: {exception.Operation}; Win32 error {exception.NativeErrorCode} ({exception.Message})");
}
