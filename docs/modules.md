# Module and DLL inspection

## Windows module concepts

A module is an executable image mapped into a process. The process executable is its primary image; DLLs and other loadable PE images are additional modules. `ModuleInspector` inventories the module snapshot for one PID, so callers can correlate a process with its executable image and loaded DLLs.

Module inventory does not establish trust. A module name or path alone does not prove a file is signed, trusted, or benign; signature verification is intentionally deferred to a later, separate module.

## Native APIs and MODULEENTRY32

```c
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme);
BOOL Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme);
```

`MODULEENTRY32W` includes the owning PID, `modBaseAddr`, `modBaseSize`, module name, and executable path. The managed `ModuleInfo` maps those to `uint`, `nuint`, `uint`, and Unicode strings respectively. `nuint` is used for `BaseAddress` because a module address is an unsigned pointer-sized value: it remains correct on both x86 and x64 and cannot imply a negative memory address.

The native structure contains both `modBaseAddr` and `hModule`; both values are valid only in the context of the owning process. The library exposes the base address for inventory and does not expose an operational raw module handle.

Before `Module32FirstW` and `Module32NextW`, `dwSize` is initialized to `Marshal.SizeOf<MODULEENTRY32W>()`. The explicit `W` APIs and fixed `WCHAR` buffers avoid ANSI/Unicode ambiguity. Structure field order and native alignment are essential because `modBaseAddr` and `hModule` are pointer-sized.

## Snapshot flags and WOW64

The inspector combines these flags:

- `TH32CS_SNAPMODULE` (`0x00000008`) requests modules matching the caller's process bitness.
- `TH32CS_SNAPMODULE32` (`0x00000010`) additionally requests 32-bit modules when the caller is 64-bit.

This gives the broadest documented Toolhelp view from a 64-bit inspector. It does not eliminate Windows architecture boundaries:

| Inspector | Target | Documented behavior |
| --- | --- | --- |
| 64-bit | 64-bit | `TH32CS_SNAPMODULE` returns 64-bit modules. |
| 64-bit | 32-bit/WOW64 | Include `TH32CS_SNAPMODULE32` to obtain 32-bit modules. |
| 32-bit | 32-bit | `TH32CS_SNAPMODULE` returns 32-bit modules. |
| 32-bit | 64-bit | Snapshot creation fails with `ERROR_PARTIAL_COPY` (299). |

Module snapshots are read-only but can race with loader activity. The implementation retries `CreateToolhelp32Snapshot` up to three times for the documented transient `ERROR_BAD_LENGTH`; if it still fails, it throws `ModuleInspectionException` with that original error. It never converts architecture or access failures into an empty list.

## Handles and failures

`SafeSnapshotHandle` owns the snapshot and calls `CloseHandle` during `using` disposal, including exceptional paths. No process or module handles are opened for this scope.

Common errors include:

- `ERROR_BAD_LENGTH` (24): a target module list changed while the snapshot was being created.
- `ERROR_ACCESS_DENIED` (5): protected targets such as Idle or CSRSS cannot be inspected by normal user-mode code.
- `ERROR_PARTIAL_COPY` (299): a 32-bit inspector attempted to snapshot a 64-bit target.
- `ERROR_NO_MORE_FILES` (18): normal completion of `Module32NextW`.

## Raw interop learning example

`examples/modules/ModuleEnumeration` uses `ModuleInspector` for a full current-process inventory and includes a compact raw `LibraryImport` demonstration. The raw version exposes `MODULEENTRY32W`, initializes `dwSize`, calls `Module32FirstW` and `Module32NextW`, represents the address as `nuint`, and closes the snapshot in `finally`. The reusable library hides this ownership behind `SafeSnapshotHandle`.

## Defensive relevance

Module inspection supports application inventory and process/module correlation. It can surface unexpected DLLs, unusual module paths, in-memory process composition changes, and candidates for later signature or reputation validation. This phase is strictly read-only: it does not load, unload, inject, manually map, or modify any module or remote process memory.

## Microsoft references

- [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
- [MODULEENTRY32W](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32w)
- [Module32FirstW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32firstw)
- [Module32NextW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32nextw)
