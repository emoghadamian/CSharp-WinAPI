using System.Runtime.InteropServices;

// Native signature: DWORD GetCurrentProcessId();
// DllImport is intentionally retained here as the explicit, traditional P/Invoke form.
[DllImport("kernel32.dll", ExactSpelling = true)]
static extern uint GetCurrentProcessId();

Console.WriteLine($"Current process ID: {GetCurrentProcessId()}");
