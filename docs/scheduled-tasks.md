# Scheduled Task inspection

`ScheduledTaskInspector` reads local Task Scheduler 2.0 metadata through the documented Task Scheduler COM automation surface. It connects only to the local service, enumerates folders/tasks, and reads task definitions; it never registers, deletes, enables, disables, runs, stops, or otherwise modifies a task.

## Bounds and lifetime

The inspector caps recursion at 16 levels, folders at 2,048, tasks at 16,384, paths at 32,768 characters, metadata strings at 16 KiB, and triggers/actions at 128 per task. Oversized or null-containing metadata fails contextually instead of being truncated.

COM is initialized for the calling execution path and uninitialized only when this laboratory initialized it. Each Task Scheduler RCW is released in `finally` immediately after conversion to immutable managed data. No COM object or native pointer is public.

## Metadata and limits

The models preserve raw task state, logon type, run level, trigger type, and action type. Exec command lines, COM-handler IDs, principal identities, triggers, and settings are data only: they are neither resolved nor executed. Inspection does not prove execution, current-user authorization, benignness, or maliciousness.

Task Subscription, registration, execution, event forwarding, ACL modification, credentials, token changes, and privilege changes are intentionally deferred. x64, x86, and ARM64 builds are supported; runtime validation remains host-architecture specific.
