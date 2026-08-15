# Learning roadmap

## Beginner

- `GetCurrentProcessId` through DllImport and LibraryImport
- native integer types, Unicode strings, and return-value error handling
- native-buffer ownership and SafeHandle

## Intermediate

- local-group enumeration and membership inspection
- process enumeration, safe process handles, image paths, sessions, and architecture
- thread enumeration, per-process filtering, and base priority
- module enumeration, paths, pointer-sized base addresses, and WOW64 behavior
- virtual-memory metadata, pointer-sized region traversal, and memory state/protection/type
- PE image headers, sections, data directories, and RVA-to-file-offset mapping
- PE Certificate Table file-offset inspection, WIN_CERTIFICATE parsing, PKCS#7/CMS metadata, and public X.509 metadata
- access-token inspection: user, groups, privileges, elevation, integrity, session, type, and impersonation level — COMPLETE
- File Security Descriptor / ACL inspection — COMPLETE
- AccessCheck / Effective Access Evaluation — COMPLETE
- Registry Security Descriptor / ACL inspection — COMPLETE
- Registry AccessCheck / Effective Access Evaluation — COMPLETE
- service inspection â€” COMPLETE
- Windows Event Log inspection — COMPLETE (subscriptions, forwarding, publishing, and log management remain deferred)
- Windows Scheduled Task inspection — COMPLETE (registration, execution, and task management remain deferred)
- Windows Handle inspection — COMPLETE (object-name/type resolution and handle manipulation remain deferred)
- Windows WMI / CIM inspection — COMPLETE (method invocation, subscriptions, persistence, and remote access remain deferred)
- Named Pipe inspection — COMPLETE (pipe connection, payload inspection, security, and ownership resolution remain deferred)
- ETW Provider metadata inspection — COMPLETE (trace sessions, provider activation, event collection, payload decoding, and provider-field queries remain deferred)

## Advanced

- token duplication, impersonation, and privilege modification (future; out of scope for the read-only token-inspection lab)
- Authenticode hashing and cryptographic signature verification
- certificate-chain, Windows trust, and CRL/OCSP validation
- documented versus NT-native API compatibility boundaries
