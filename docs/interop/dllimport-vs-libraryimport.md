# DllImport and LibraryImport

Both attributes call an exported function in a native DLL. `DllImport` is the classic runtime-generated P/Invoke mechanism; the `01-dllimport` example intentionally makes that declaration visible. `LibraryImport` generates the marshalling stub at build time and is used by the reusable Netapi32 implementation.

```csharp
// Native: DWORD GetCurrentProcessId();
[DllImport("kernel32.dll", ExactSpelling = true)]
static extern uint GetCurrentProcessId();

[LibraryImport("kernel32.dll", EntryPoint = "GetCurrentProcessId")]
internal static partial uint GetCurrentProcessId();
```

`DWORD` is an unsigned 32-bit integer, so `uint` is used. The function has no Unicode/ANSI variant, making `ExactSpelling = true` appropriate in the DllImport example.

## CsWin32

CsWin32 is planned as a separate, opt-in learning example. It will import documented Windows SDK metadata through `Microsoft.Windows.CsWin32`, rather than a hand-copied declaration. It is not yet a dependency of the core library so that learners can inspect the generated-vs-manual tradeoff without obscuring the raw API signatures.
