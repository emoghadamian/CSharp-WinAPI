# Windows Handle inspection

`HandleInspector` performs metadata-only inventory of the system handle table through `NtQuerySystemInformation(SystemExtendedHandleInformation)`. A handle value is meaningful only in its owning process; it is not the underlying kernel object and does not grant access to that object.

The NT layout is internal and architecture-dependent: pointer-sized fields use `nuint`, while the public model exposes only PID, handle value, type index, granted access, attributes, and creator backtrace index. Kernel object pointers are deliberately omitted. `NTSTATUS` is preserved directly and is not treated as `GetLastError`.

The growable response buffer starts at 64 KiB and is capped at 64 MiB. The parser validates header/entry ranges, count multiplication, PID representability, and a one-million-entry bound before materializing immutable snapshots. Filtering works only over that already collected metadata.

This laboratory does not duplicate, close, read from, write through, or query underlying foreign handles. It does not open target processes, access memory, or change system state. `NtQuerySystemInformation` is an NT implementation contract rather than a stable Win32 ABI; cross-bitness behavior must be validated on the target host. Runtime validation is currently x64 only.
