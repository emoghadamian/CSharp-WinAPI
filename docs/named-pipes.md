# Named Pipe inspection

`NamedPipeInspector` inventories names visible in the local `\\.\pipe\*` namespace through documented `FindFirstFileW` and `FindNextFileW` enumeration. Its internal search handle is released only with `FindClose`, never `CloseHandle`. The resulting `IReadOnlyList<NamedPipeInfo>` is a detached, immutable snapshot.

The result contains only the authoritative pipe name and local path. The laboratory does not open or connect to a pipe, read or write payloads, accept clients, impersonate clients, duplicate handles, resolve owners, or inspect pipe security. A pipe name is metadata, not proof of server identity, client identity, authorization, or maliciousness.

Enumeration is limited to 16,384 names. Each fixed-buffer Unicode name must be nonempty, null-terminated, no more than 259 characters, and unique within the snapshot. `ERROR_NO_MORE_FILES` is normal completion; `ERROR_FILE_NOT_FOUND` on the initial wildcard search is an empty namespace. Other Win32 failures remain contextual exceptions.

Owner PID/process, client identity, security descriptor, authorization decisions, payload/content, and proof of maliciousness are intentionally deferred: safely collecting any of them requires separate APIs and is outside this metadata-only laboratory.
