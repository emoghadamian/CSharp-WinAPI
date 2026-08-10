# Virtual-memory inspection

## Scope and safety boundary

`VirtualMemoryInspector` inventories virtual-memory metadata for one local process. It opens the process, asks Windows to describe address ranges, and closes the handle. It does **not** read bytes or perform any memory mutation. The following APIs and activities are deliberately absent from this phase:

- `ReadProcessMemory`, `WriteProcessMemory`, and byte-content collection.
- `VirtualAllocEx`, `VirtualFreeEx`, `VirtualProtectEx`, or any allocation/protection change.
- Section mapping, remote-thread APIs, code injection, or process manipulation.

This makes the module suitable for defensive inventory, diagnostics, and learning about address-space layout without changing the inspected process.

## Native APIs and access

```c
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress,
                      PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
BOOL CloseHandle(HANDLE hObject);
```

`VirtualQueryEx` requires a process handle opened with `PROCESS_QUERY_INFORMATION` (`0x0400`), which is the documented minimum right. The library requests exactly that right, not broad process access. Access can still be denied for protected/system processes, hardened security descriptors, or targets that terminate while the query runs. `OpenProcess` and `VirtualQueryEx` failures become `MemoryInspectionException`, preserving both the operation name and the original Win32 error code.

The reusable library uses the existing `SafeProcessHandle`, so every successfully opened handle is released with `CloseHandle` even when enumeration fails. The raw example shows the equivalent explicit `try`/`finally` cleanup.

## MEMORY_BASIC_INFORMATION and managed mapping

`MEMORY_BASIC_INFORMATION` is architecture-sensitive. Its `BaseAddress`, `AllocationBase`, and `RegionSize` fields are `PVOID`, `PVOID`, and `SIZE_T`, respectively. The native layout uses `nint`/`nuint`; public `MemoryRegionInfo` exposes the two addresses and size as unsigned pointer-sized `nuint` values.

| Native field | Managed field | Meaning |
| --- | --- | --- |
| `BaseAddress` | `BaseAddress` | First address in this contiguous reported region. |
| `AllocationBase` | `AllocationBase` | First address of the originating allocation when defined. |
| `RegionSize` | `RegionSize` | Byte length of the reported range. |
| `State` | `State` / `RawState` | `MEM_COMMIT`, `MEM_RESERVE`, or `MEM_FREE`. |
| `Protect` | `Protection` / `RawProtection` | Current protection flags when defined. |
| `AllocationProtect` | `AllocationProtection` / `RawAllocationProtection` | Initial allocation protection when available. |
| `Type` | `Type` / `RawType` | `MEM_PRIVATE`, `MEM_MAPPED`, or `MEM_IMAGE` when defined. |

The raw `uint` properties retain exactly what Windows reported, while the enum properties make common values readable. `MEM_FREE` leaves allocation, protection, and type fields undefined; reserved regions also have undefined current protection. Consumers should therefore interpret these values only where the documented state permits them.

## Traversal model

`VirtualQueryEx` returns the contiguous range beginning at the supplied address whose pages have matching attributes. The inspector starts at address zero and advances with:

```text
nextAddress = BaseAddress + RegionSize
```

It obtains the caller-visible maximum application address through `GetSystemInfo`, stops after the region that extends beyond it, and rejects zero-sized, non-advancing, or overflowing ranges. A native query failure—including a target exiting during traversal—is never converted into an empty or partial result. This prevents endless loops and preserves useful failure evidence.

## States, protections, and types

- `MEM_COMMIT` (`0x1000`) has physical storage in RAM or the paging file.
- `MEM_RESERVE` (`0x2000`) reserves address space without physical storage.
- `MEM_FREE` (`0x10000`) is unallocated address space.

`MemoryProtection` includes the documented base flags `PAGE_NOACCESS`, read/write/copy-on-write, execute variants, plus `PAGE_GUARD`, `PAGE_NOCACHE`, `PAGE_WRITECOMBINE`, and the `0x40000000` CFG target flag. `MemoryType` maps `MEM_PRIVATE`, `MEM_MAPPED`, and `MEM_IMAGE`.

`MEM_IMAGE` indicates an image-section mapping. It is useful to compare with `ModuleInspector` results, but it is not a one-to-one module list: a single module can span several memory regions with different protections, and not every image-backed range should be treated as a separately loaded module. Likewise, `MEM_MAPPED` does not establish that a mapped file is suspicious or benign.

## Cross-architecture behavior

The inspector preserves the pointer width of the running .NET process. It is appropriate for same-bitness inspection: an x64 build represents x64 virtual addresses and an x86 build represents x86 addresses. A 32-bit inspector cannot represent the virtual addresses of a 64-bit target with this native `MEMORY_BASIC_INFORMATION` layout. Windows documents explicit `MEMORY_BASIC_INFORMATION32` and `MEMORY_BASIC_INFORMATION64` layouts for debuggers that need cross-architecture support; that specialized path is intentionally not implemented here. Run a matching-bitness inspector rather than assuming a 32-bit caller can fully inventory a 64-bit process.

## Example

`examples/memory/VirtualMemoryInspection` inspects its current process by default. It displays total and committed-region counts, then caps output at the first 80 committed ranges so normal processes do not produce an unusably large listing. Alongside the managed wrapper it contains a small raw `LibraryImport` demonstration with visible `OpenProcess`, `VirtualQueryEx`, `MEMORY_BASIC_INFORMATION`, and `CloseHandle` declarations.

## Defensive relevance and limitations

Metadata can help establish an address-space baseline, correlate image-backed mappings with module inventory, identify guarded or executable regions for later investigation, and notice unusual region distributions. It does not prove code provenance, signature state, in-memory contents, or maliciousness. Copy-on-write pages can continue to be reported as `MEM_MAPPED` or `MEM_IMAGE`; determining private copy-on-write state requires other APIs and is out of scope.

## Microsoft references

- [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
- [MEMORY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information)
- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [Memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [GetSystemInfo](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo)
