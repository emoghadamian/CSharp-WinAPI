# Thread inspection

## Process and thread relationship

A Windows process owns resources such as an address space and handles. A thread is an execution context within that process: it has its own thread ID, scheduling priority, and CPU execution state.

```text
Process
  ├── Thread
  ├── Thread
  └── Thread
```

`ThreadInspector` inventories the relationship exposed by Toolhelp32: each `ThreadInfo` contains a thread ID, owning process ID, and kernel base priority. `EnumerateProcessThreads(processId)` filters this read-only snapshot relationship without opening a thread handle.

## Snapshot enumeration

```c
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
BOOL Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
```

The inspector calls `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)`, then walks `THREADENTRY32` entries with `Thread32First` and `Thread32Next`. The snapshot is point-in-time and read-only.

`THREADENTRY32` has this native layout:

```c
typedef struct tagTHREADENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ThreadID;
  DWORD th32OwnerProcessID;
  LONG  tpBasePri;
  LONG  tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32;
```

The C# declaration maps `DWORD` to `uint` and `LONG` to `int`. There are no pointer-sized fields, so this layout is the same on x86 and x64. Before every `Thread32First` or `Thread32Next` call, `dwSize` is set to `Marshal.SizeOf<THREADENTRY32>()`; without initialization, `Thread32First` fails. The API can report a smaller written size on older systems, so the library validates that the fields it uses are present.

## Priority and identifiers

- `th32ThreadID` is the system thread identifier.
- `th32OwnerProcessID` identifies the process that created the thread.
- `tpBasePri` is the kernel base priority, from 0 (lowest) to 31 (highest).

`tpDeltaPri`, `cntUsage`, and `dwFlags` are not used by the current documented Toolhelp contract and are not exposed by the managed abstraction.

## Handles, access rights, and errors

This scope needs no `OpenThread` call. Toolhelp thread enumeration therefore avoids requesting `THREAD_QUERY_INFORMATION` or `THREAD_QUERY_LIMITED_INFORMATION`, and it does not expose raw `IntPtr` thread handles to consumers.

The only owned native resource is the Toolhelp snapshot handle. `SafeSnapshotHandle` closes it with `CloseHandle` in a `using` scope. A future thread-detail module that opens a thread must use a SafeHandle and request only the minimal documented access right.

The APIs return `BOOL`, so their declarations use `SetLastError = true` and failures read `Marshal.GetLastPInvokeError()`. `ERROR_NO_MORE_FILES` is normal completion; snapshot creation can still fail due to system or privilege restrictions. Protected processes can restrict additional handle-based inspection, but they do not require a handle for this snapshot-only inventory.

## Raw interop learning example

`examples/threads/ThreadEnumeration` first uses `ThreadInspector`, then includes a minimal raw `LibraryImport` example. It visibly declares `THREADENTRY32`, initializes `dwSize`, calls `Thread32First`, and releases the raw snapshot handle in `finally` with `CloseHandle`. The reusable library keeps that ownership behind `SafeSnapshotHandle`.

## Defensive relevance

Thread counts and process-to-thread relationships help baseline normal execution behavior. Investigators can identify unexpected thread growth, correlate unusual process activity, and connect thread telemetry to a process inventory. This module intentionally stops at documented, read-only enumeration: it does not inject, suspend, alter context, queue APCs, terminate threads, or access remote memory.

## Microsoft references

- [THREADENTRY32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32)
- [Thread32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first)
- [Thread32Next](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next)
- [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
