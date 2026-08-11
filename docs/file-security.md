# File security descriptor and ACL inspection

`FileSecurityInspector` reads owner, group, DACL, ACE, SID, access-mask, inheritance, and descriptor-control metadata for files and directories through `GetNamedSecurityInfoW`. It requests only owner, group, and DACL information; SACL and mandatory integrity labels are deferred because they require privilege-dependent access.

The returned descriptor buffer is owned by `SafeSecurityDescriptorHandle` and released with `LocalFree`; pointers to its owner, group, DACL, and ACEs are parsed only while that owner remains alive. A null DACL (permits all access), an empty DACL (permits none), and an absent DACL are represented separately.

ACL inspection is not effective-access evaluation. An allow ACE does not guarantee access: Windows considers the caller token's SIDs, deny ACEs, requested access, inheritance, privileges, integrity policy, and other rules. This lab does not call `AccessCheck`, modify ACLs, tokens, or privileges.
