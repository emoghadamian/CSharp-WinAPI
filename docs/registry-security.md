# Registry security descriptor and ACL inspection

`RegistrySecurityInspector` reads owner, group, DACL, ordered ACE, and security-descriptor control metadata for a local registry subkey. It opens only explicitly named subkeys beneath `HKEY_CLASSES_ROOT`, `HKEY_CURRENT_USER`, `HKEY_LOCAL_MACHINE`, `HKEY_USERS`, or `HKEY_CURRENT_CONFIG`; predefined root handles are never owned or closed.

The inspector calls `RegOpenKeyExW` with only `READ_CONTROL`, then uses `RegGetKeySecurity` for owner, group, and DACL information. These registry APIs return `LSTATUS`; their failures are preserved in `RegistrySecurityException` and are not read from `GetLastError`. The descriptor is a caller-owned managed `byte[]`, bounded at 16 MiB, pinned only while native descriptor pointers are parsed, then deterministically released with its opened `SafeRegistryKeyHandle`.

`RegistryKeyPath` makes the selected `RegistryView` explicit. `Registry32` and `Registry64` add only the documented `KEY_WOW64_32KEY` or `KEY_WOW64_64KEY` selection flag to `RegOpenKeyExW`; they are view selectors, not authorization masks. `Default` uses the process default view.

The result distinguishes an absent DACL, a NULL DACL, and an empty DACL. Supported allow, deny, and audit ACE layouts retain their raw type, flags, access mask, and authoritative SID string; unsupported ACE layouts retain their raw type and flags without guessing their payload. Account-name translation is best-effort only.

ACL inspection is not equivalent to effective authorization. In particular, an allow ACE does not establish that a token will receive access. Use `RegistryAccessCheckInspector` when evaluating the current process token against the same kind of descriptor, while remembering that AccessCheck is still not an explanation of every Windows authorization mechanism.

This laboratory is local and read-only. It does not enumerate values, create/delete keys, modify registry ACLs, request SACLs, use remote-registry APIs, or alter tokens or privileges.
