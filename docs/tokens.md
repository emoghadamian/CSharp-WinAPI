# Access-token inspection

An access token is Windows' security context for a process or thread. This laboratory reads a process primary token through [OpenProcessToken](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken) and [GetTokenInformation](https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation). It requests only `TOKEN_QUERY`; it does not change a token.

## What the library reports

`TokenInspector.InspectCurrentProcessToken()` and `InspectProcessToken(uint)` return an immutable `TokenInfo` snapshot. The latter opens the target with `PROCESS_QUERY_LIMITED_INFORMATION`, then opens its token with `TOKEN_QUERY`. Protected or inaccessible targets raise `TokenInspectionException`, which retains the operation, PID, and native error code rather than returning an empty token.

- **User**: the authoritative user SID and an optional account-name translation. SID translation is best-effort; an unresolved name never removes the SID.
- **Groups**: every `TOKEN_GROUPS` SID and the unmodified group-attribute bits.
- **Privileges**: every `TOKEN_PRIVILEGES` LUID, best-effort display name, attributes, and derived enabled states. A lookup failure preserves the LUID.
- **Elevation**: `TokenElevation` supplies `IsElevated`. Administrator-group membership alone does not establish elevation.
- **Integrity**: `TokenIntegrityLevel` supplies a mandatory-label SID and RID. Known RIDs map to Untrusted, Low, Medium, MediumPlus, High, System, or Protected; other values remain `Unknown` with their raw SID and RID.
- **Session, type, and impersonation level**: `TokenSessionId`, `TokenType`, and, for an impersonation token, `TokenImpersonationLevel`. Raw enum values are retained so future Windows values are not silently collapsed.

Membership, privilege, elevation, and integrity are separate security concepts. Being in an Administrators group does not necessarily mean the token is elevated, and being elevated does not imply every privilege is enabled.

## Native buffer and handle lifecycle

Each variable-length token query uses the documented two-call `GetTokenInformation` pattern: obtain the required size from `ERROR_INSUFFICIENT_BUFFER`, validate and bound it, allocate exactly that amount, then query and parse with checked offsets. SID pointers and flexible-array entries are validated against the pinned result buffer before they are read.

`SafeTokenHandle` owns the access-token handle and closes it through [CloseHandle](https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle). The process and token handles are scoped with `using`, so failure paths remain deterministic. Public results expose neither handles nor native pointers, and their collections are immutable snapshots.

## Primary and impersonation tokens

Processes normally use **primary tokens**. **Impersonation tokens** represent a client security context on a thread or server operation and carry an impersonation level. `TokenInspector` only identifies and reports those states; it never creates, assigns, or impersonates a token. The separate AccessCheck laboratories internally duplicate the current process primary token only when the native `AccessCheck` contract requires an impersonation token; that SafeHandle-owned token is supplied only to that call and immediately disposed.

## Scope and limitations

The example and library are inspection-only. They do not modify privileges, impersonate users, acquire credentials, or create processes under another token. The narrowly scoped internal duplication used by AccessCheck is not exposed through this API and is not available for any other operation. Access checks are enforced by Windows, so a token for another process can legitimately fail with access denied. Account and privilege-name resolution can also vary with local/domain configuration, while raw SIDs and LUIDs remain available.
