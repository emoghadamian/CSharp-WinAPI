# AccessCheck / effective access evaluation

`AccessCheckInspector` evaluates the current process token against a file or directory security descriptor. It acquires a descriptor for the call lifetime, opens only the current process token with `TOKEN_QUERY | TOKEN_DUPLICATE`, and uses `DuplicateToken` only to satisfy `AccessCheck`'s impersonation-token contract. The temporary token is never impersonated, exposed, persisted, or used outside the native evaluation.

The result preserves requested, mapped, and granted `ACCESS_MASK` values plus `PRIVILEGE_SET` metadata. `GENERIC_MAPPING` translates generic file rights before the call. `IsGranted=false` is a completed authorization decision, not an API failure; descriptor acquisition, token acquisition, and native `AccessCheck` failures throw contextual exceptions.

ACL inspection tells you what rules exist. AccessCheck evaluates a specific token against those rules. AccessCheck does not provide a complete explanation of every authorization decision: DACL ACE ordering, token SIDs, privileges, requested access, and other Windows rules matter. File/directory and local-registry evaluation are available through separate public inspectors with their own generic mappings; service evaluation, ACL modification, authorization explanation, and actual impersonation are out of scope.
