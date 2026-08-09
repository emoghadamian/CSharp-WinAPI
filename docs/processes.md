# Process inspection

## Windows process concepts

A Windows process is an executing program instance identified by a process identifier (PID). A PID can be reused after a process exits, so it is useful for a point-in-time investigation but is not a permanent identity. Toolhelp's `PROCESSENTRY32W.th32ParentProcessID` records the parent PID observed in the same snapshot.

`ProcessInspector` intentionally combines two layers:

1. A read-only Toolhelp32 snapshot supplies PID, parent PID, and executable filename for every visible process.
2. A `SafeProcessHandle` opened with `PROCESS_QUERY_LIMITED_INFORMATION` supplies optional extended data for each process.

This lets enumeration remain useful when protected, elevated, or cross-user processes reject an extended query.

## Native APIs and C# interop

```c
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
BOOL Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);
```

`DWORD` maps to `uint`; `HANDLE` maps to an internal SafeHandle rather than a public `IntPtr`; `BOOL` is explicitly marshalled as a C# `bool`; and the fixed `WCHAR[MAX_PATH]` Toolhelp filename buffer is represented by a fixed `char` buffer. The library calls the explicit `W` exports to avoid ANSI/Unicode ambiguity.

`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` creates a read-only point-in-time snapshot. `PROCESSENTRY32W.dwSize` must be set before `Process32FirstW`; the first/next APIs use `GetLastError` and finish with `ERROR_NO_MORE_FILES`.

## Extended information

- `QueryFullProcessImageNameW` retrieves an executable path with a query-limited handle.
- `GetProcessTimes` returns `FILETIME`; creation time is exposed as UTC.
- `ProcessIdToSessionId` returns a Remote Desktop Services session ID when permissions allow.
- `IsWow64Process2` returns process and native machine types. On older systems the implementation falls back to `IsWow64Process`.

`IsWow64Process2` needs `PROCESS_QUERY_INFORMATION` or `PROCESS_QUERY_LIMITED_INFORMATION`; `PROCESS_QUERY_LIMITED_INFORMATION` is deliberately requested because it grants the least access needed by the main inspection APIs. `ProcessIdToSessionId` can still be denied on restricted processes, in which case `SessionId` is null and the Win32 code is retained in `InspectionErrorCode`.

## Handles and errors

Snapshot and process handles are owned by `SafeSnapshotHandle` and `SafeProcessHandle`. Their `ReleaseHandle` methods call `CloseHandle`, and all ownership scopes use `using`; callers never receive a raw process handle.

The Kernel32 APIs in this module return either `BOOL` or `INVALID_HANDLE_VALUE`, so declarations use `SetLastError = true` and failures read `Marshal.GetLastPInvokeError()`. Common outcomes include:

- `ERROR_ACCESS_DENIED` for protected, elevated, or cross-user processes.
- `ERROR_INVALID_PARAMETER` for an unavailable PID.
- `ERROR_NO_MORE_FILES` as normal snapshot-enumeration completion.
- `ERROR_CALL_NOT_IMPLEMENTED` on systems without `IsWow64Process2`.

An access-denied extended query does not remove the Toolhelp entry. It is represented by missing optional fields and `InspectionErrorCode`, rather than being silently treated as success.

## x86, x64, and WOW64

`PROCESSENTRY32W` contains a pointer-sized `ULONG_PTR`, represented as `nuint`; its native layout therefore remains correct for x86 and x64. `IsWow64Process2` distinguishes the target process architecture from the native operating-system architecture. `QueryFullProcessImageNameW` is also suitable for retrieving image names across 32-bit/64-bit boundaries.

## Raw interop learning example

`examples/processes/ProcessEnumeration` demonstrates `ProcessInspector` and includes a deliberately small raw `LibraryImport` call to `QueryFullProcessImageNameW` for the current-process pseudo-handle. The pseudo-handle must not be closed; unlike it, every real snapshot or process handle in the reusable library is owned by a SafeHandle.

## Defensive relevance

Process inventory is a core triage signal: unexpected executable paths, suspicious parent-child relationships, processes running in unexpected sessions, and unusual architecture combinations can indicate investigation leads. A snapshot can become stale immediately, so consumers should treat the result as a point-in-time observation and correlate it with creation time and other telemetry.

## Microsoft references

- [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
- [Process32FirstW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32firstw) and [Process32NextW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw)
- [IsWow64Process2](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2)
- [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
- [ProcessIdToSessionId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-processidtosessionid)
