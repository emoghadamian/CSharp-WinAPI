# 🪟 CSharp-WinAPI

A practical C# laboratory for Win32 API interop, Windows Internals, and read-only defensive-security investigation.

## 🎯 Project Goals

- Build small, reusable abstractions over documented Windows APIs.
- Teach the complete path from C# declarations to native Windows concepts.
- Prioritize inspection and investigation over modification or offensive use.

```text
C# → .NET interop → native Windows types → Win32 API → Windows Internals → defensive investigation
```

## 🎓 What You Will Learn

- P/Invoke, `DllImport`, `LibraryImport`, and the future CsWin32 track
- Unicode strings, `DWORD`, pointer-sized values, structures, buffers, and marshalling
- Native resource ownership, `SafeHandle`, `NET_API_STATUS`, and Windows error handling
- Local-group membership investigation as a first defensive-security module

## 🔗 C# Interop

The core library uses `LibraryImport` for its modern, source-generated Netapi32 stubs. The learning examples retain an explicit `DllImport` declaration so the native signature remains easy to inspect. CsWin32 is intentionally documented but not yet a core dependency.

See [DllImport vs LibraryImport](docs/interop/dllimport-vs-libraryimport.md).

## 🧩 P/Invoke

`src/CSharp.WinAPI/Interop` contains raw declarations only. Managed logic lives separately in feature-focused namespaces; no application flow is embedded in native declarations.

## ⚙️ Win32 APIs

The first module uses `Netapi32.dll`:

- `NetLocalGroupEnum` enumerates local groups using `LOCALGROUP_INFO_0`.
- `NetLocalGroupGetMembers` returns `LOCALGROUP_MEMBERS_INFO_2` member data.
- `NetApiBufferFree` releases every system-owned result buffer through a SafeHandle.
- Toolhelp32 process APIs enumerate PID, parent PID, and executable names.
- Kernel32 query APIs provide image path, creation time, session, and architecture when allowed.

Both enumeration APIs preserve their `NET_API_STATUS` return code in `NetApiException`; they do not substitute `GetLastError`.

## 🧠 Windows Internals

The current modules introduce local security groups, SID usage, account membership, RPC-allocated result buffers, Toolhelp process/thread/module snapshots, process handles, session IDs, thread priorities, module base addresses, WOW64 architecture, and virtual-memory region metadata. Token, service, registry, and window modules are planned next.

## 🔍 Process Inspection

Implemented read-only inspection through `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`, `OpenProcess`, `QueryFullProcessImageNameW`, `GetProcessTimes`, `ProcessIdToSessionId`, and `IsWow64Process2`.

See [Process inspection](docs/processes.md).

## 🧵 Thread APIs

Implemented read-only Toolhelp thread enumeration through `Thread32First` and `Thread32Next`. `ThreadInspector` exposes thread ID, owning PID, base priority, and per-process filtering without opening thread handles.

See [Thread inspection](docs/threads.md).

## 💾 Memory APIs

Implemented read-only virtual-memory metadata inspection through `OpenProcess` and `VirtualQueryEx`. `VirtualMemoryInspector` exposes pointer-sized region addresses and sizes, state, protections, allocation protection, and type without reading or modifying process memory.

See [Virtual-memory inspection](docs/memory.md).

## 📦 Module / DLL APIs

Implemented read-only Toolhelp module enumeration through `Module32FirstW` and `Module32NextW`. `ModuleInspector` exposes name, path, unsigned pointer-sized base address, image size, and owning PID.

See [Module and DLL inspection](docs/modules.md).

## 🔐 Security APIs

Implemented: read-only local-group and member enumeration.

Planned: access tokens, users, privileges, integrity levels, and elevation state.

## 🛡️ Blue Team Use Cases

- Identify local-administrator and remote-management group membership.
- Establish a baseline of local security groups and account assignments.
- Surface access-denied and partial-result conditions instead of silently hiding them.

The project does not implement credential theft, process injection, or memory modification workflows.

## 🗂️ Project Structure

```text
src/CSharp.WinAPI/                 reusable library
  Interop/Netapi32/                raw documented native declarations and native layouts
  Interop/Kernel32/                raw process declarations, layouts, and SafeHandles
  LocalGroups/                     managed read-only local-group abstraction
  Processes/                       managed read-only process abstraction
  Threads/                         managed read-only thread abstraction
  Modules/                         managed read-only module abstraction
  Memory/                          managed read-only virtual-memory metadata abstraction
examples/learning/                 minimal interop demonstrations
examples/security/                 defensive investigation examples
examples/processes/                process inspection examples
examples/threads/                  thread inspection examples
examples/modules/                  module and DLL inspection examples
examples/memory/                   virtual-memory inspection examples
tests/CSharp.WinAPI.Tests/         dependency-free executable integration tests
docs/                              interop guidance, security notes, and roadmap
```

## 🚀 Getting Started

Requirements: Windows and the .NET 8 SDK.

```powershell
dotnet restore CSharp-WinAPI.sln
dotnet build CSharp-WinAPI.sln --configuration Debug
dotnet run --project examples/security/LocalGroupInspection
```

## 🧪 Testing

The test runner exercises local-group enumeration, member enumeration, and invalid-group native error handling without requiring Administrator privileges:

```powershell
dotnet run --project tests/CSharp.WinAPI.Tests --configuration Debug
```

## 📚 Learning Path

1. `examples/learning/01-dllimport` — traditional P/Invoke.
2. `examples/learning/02-libraryimport` — generated modern P/Invoke.
3. `docs/security/local-group-inspection.md` — native buffers, errors, pagination, and defensive relevance.
4. `examples/processes/ProcessEnumeration` — Toolhelp snapshots and safe process inspection.
5. `examples/threads/ThreadEnumeration` — Toolhelp thread snapshots and process-to-thread relationships.
6. `examples/modules/ModuleEnumeration` — module snapshots, addresses, and cross-architecture limits.
7. `examples/memory/VirtualMemoryInspection` — virtual-memory region metadata and safe traversal.
8. See the [full roadmap](docs/roadmap.md).

## ⚠️ Privileges & Windows Version Considerations

The module targets Windows and uses Unicode Netapi32 APIs available since Windows 2000. Local queries normally work for authenticated users; remote, domain-controller, and hardened environments may return access-denied or partial-result statuses. `DWORD_PTR` resume handles are represented as `nuint`, preserving x86/x64 correctness.

## API Coverage

| Category | API | Implemented | Tested | Documented |
| --- | --- | --- | --- | --- |
| Local groups | `NetLocalGroupEnum` | Yes | Yes | Yes |
| Local groups | `NetLocalGroupGetMembers` | Yes | Yes | Yes |
| Native buffers | `NetApiBufferFree` via `NetApiBufferSafeHandle` | Yes | Indirectly | Yes |
| Interop learning | `GetCurrentProcessId` with `DllImport` | Example | Example run | Yes |
| Interop learning | `GetCurrentProcessId` with `LibraryImport` | Example | Example run | Yes |
| Interop learning | CsWin32 | Planned | No | Yes |
| Processes | `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW` | Yes | Yes | Yes |
| Processes | `OpenProcess` with SafeHandle | Yes | Indirectly | Yes |
| Processes | `QueryFullProcessImageNameW` | Yes | Yes | Yes |
| Processes | `GetProcessTimes` | Yes | Indirectly | Yes |
| Processes | `ProcessIdToSessionId` | Yes | Indirectly | Yes |
| Processes | `IsWow64Process2` with compatibility fallback | Yes | Yes | Yes |
| Threads | `CreateToolhelp32Snapshot` with `TH32CS_SNAPTHREAD` | Yes | Yes | Yes |
| Threads | `Thread32First`, `Thread32Next`, `THREADENTRY32` | Yes | Yes | Yes |
| Modules | `CreateToolhelp32Snapshot` with module flags | Yes | Yes | Yes |
| Modules | `Module32FirstW`, `Module32NextW`, `MODULEENTRY32W` | Yes | Yes | Yes |
| Virtual memory | `OpenProcess` with `PROCESS_QUERY_INFORMATION` | Yes | Yes | Yes |
| Virtual memory | `VirtualQueryEx`, `MEMORY_BASIC_INFORMATION` | Yes | Yes | Yes |

## 🤝 Contributing

Keep raw interop, managed wrappers, examples, tests, and documentation separate. Add documented Windows API sources, state resource ownership, preserve native error semantics, and do not claim unvalidated coverage.

## 📄 License

No license file is currently present. Add an explicit license before distributing or accepting external contributions.
