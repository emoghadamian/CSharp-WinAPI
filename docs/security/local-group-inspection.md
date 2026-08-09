# Local-group inspection

`LocalGroupInspector` is a read-only wrapper around two documented Netapi32 APIs:

- `NetLocalGroupEnum` at level 0 returns `LOCALGROUP_INFO_0` entries.
- `NetLocalGroupGetMembers` at level 2 returns `LOCALGROUP_MEMBERS_INFO_2` entries.

## Native and C# signatures

```c
NET_API_STATUS NetLocalGroupEnum(
  LPCWSTR servername, DWORD level, LPBYTE *bufptr, DWORD prefmaxlen,
  LPDWORD entriesread, LPDWORD totalentries, PDWORD_PTR resumehandle);
```

The core declaration maps `LPCWSTR` to `string?`, `DWORD` to `uint`, `LPBYTE *` to `out IntPtr`, `LPDWORD` to `out uint`, and the pointer-sized `PDWORD_PTR` payload to `ref nuint`. `null` as `servername` means the current computer. Level `0` selects `LOCALGROUP_INFO_0`, whose only field is an `LPWSTR` group name.

`NetLocalGroupGetMembers` has the same buffer and pagination parameters, with an additional `LPCWSTR localgroupname`; level `2` selects `LOCALGROUP_MEMBERS_INFO_2` (`PSID`, `SID_NAME_USE`, and `LPWSTR`). Pointers are decoded before the owning buffer is disposed.

Both APIs allocate their result buffer. The caller owns that buffer and must release it with `NetApiBufferFree`, even when the API returns `ERROR_MORE_DATA`. `NetApiBufferSafeHandle` makes this ownership explicit and guarantees release during exceptions.

The native APIs return `NET_API_STATUS`; this is the error value to preserve in `NetApiException`. They do not use `GetLastError` as their primary failure channel.

## Defensive relevance

Local-group membership helps investigators identify privileged access, remote-management exposure, and unexpected account assignments. Access may be denied on remote systems or protected configurations; tools must report that native status rather than silently returning incomplete data.

## Architecture considerations

`DWORD_PTR` resume handles are pointer-sized. The wrapper uses `nuint`, works on x86 and x64, and continues calls while the API returns `ERROR_MORE_DATA`. Only `entriesRead` is used to traverse each returned buffer; `totalEntries` is informational.

Common outcomes are `ERROR_ACCESS_DENIED`, `ERROR_MORE_DATA`, and group-not-found statuses. They are exposed through `NetApiException.NativeErrorCode`, preserving the original value for investigators. The APIs require Windows; their documented minimum client is Windows 2000, but permissions and the result set vary for domain controllers, remote servers, and hardened hosts.
