# Registry AccessCheck / effective access evaluation

`RegistryAccessCheckInspector` evaluates the current process token against the DACL of a local registry subkey. It obtains the descriptor with the same `READ_CONTROL`-only, caller-owned, pinned-buffer path used by `RegistrySecurityInspector`.

For the native `AccessCheck` token contract only, the shared internal bridge opens the current process primary token with `TOKEN_QUERY | TOKEN_DUPLICATE`, calls `DuplicateToken(SecurityImpersonation)`, supplies that lifetime-scoped impersonation token to `AccessCheck`, and disposes it immediately. It never impersonates a thread or process, exposes a raw token handle, modifies privileges, persists a token, accesses credentials, or creates a process.

Registry generic rights use the registry `GENERIC_MAPPING` exactly:

| Generic right | Registry access mask |
| --- | --- |
| `GENERIC_READ` | `0x00020019` |
| `GENERIC_WRITE` | `0x00020006` |
| `GENERIC_EXECUTE` | `0x00020019` |
| `GENERIC_ALL` | `0x000F003F` |

`KEY_WOW64_32KEY` and `KEY_WOW64_64KEY` are deliberately absent because they select a registry view; they are not registry authorization rights. `EffectiveAccessResult` retains the original desired mask, mapped desired mask, granted mask, decision, and immutable `PRIVILEGE_SET` metadata. A returned denial is a successful AccessCheck result; descriptor/token/API failures throw a contextual exception instead.

AccessCheck evaluates the supplied token and security descriptor. It does not explain every Windows authorization mechanism, and this laboratory does not implement an authorization explanation engine, ACL changes, service/registry writes, remote registry, or arbitrary-token evaluation.
