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

`src/CSharp.WinAPI/Interop` contains raw declarations only. Managed logic lives separately in `src/CSharp.WinAPI/LocalGroups`; no application flow is embedded in native declarations.

## ⚙️ Win32 APIs

The first module uses `Netapi32.dll`:

- `NetLocalGroupEnum` enumerates local groups using `LOCALGROUP_INFO_0`.
- `NetLocalGroupGetMembers` returns `LOCALGROUP_MEMBERS_INFO_2` member data.
- `NetApiBufferFree` releases every system-owned result buffer through a SafeHandle.

Both enumeration APIs preserve their `NET_API_STATUS` return code in `NetApiException`; they do not substitute `GetLastError`.

## 🧠 Windows Internals

The current module introduces local security groups, SID usage, account membership, RPC-allocated result buffers, and pointer-sized pagination handles. Process, thread, memory, token, service, registry, and window modules are planned next.

## 🔍 Process Inspection

Planned. The next laboratory will cover `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `OpenProcess`, image paths, architecture, modules, and memory-region metadata.

## 🧵 Thread APIs

Planned after the Process API laboratory.

## 💾 Memory APIs

Planned as read-only `VirtualQueryEx` and `ReadProcessMemory` inspection. Memory-writing APIs are intentionally out of scope for the core library.

## 📦 Module / DLL APIs

Planned for documented process-module enumeration and image metadata.

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
  LocalGroups/                     managed read-only inspection abstractions
examples/learning/                 minimal interop demonstrations
examples/security/                 defensive investigation examples
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
4. See the [full roadmap](docs/roadmap.md).

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
| Processes | Process inspection APIs | Planned | No | Planned |

## 🤝 Contributing

Keep raw interop, managed wrappers, examples, tests, and documentation separate. Add documented Windows API sources, state resource ownership, preserve native error semantics, and do not claim unvalidated coverage.

## 📄 License

No license file is currently present. Add an explicit license before distributing or accepting external contributions.
