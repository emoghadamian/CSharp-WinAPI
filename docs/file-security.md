# File security descriptor and ACL inspection

`FileSecurityInspector` reads a Windows security descriptor for files and directories. It exposes the owner and primary-group SIDs, DACL, ordered ACEs, raw `ACCESS_MASK` values, inheritance flags, and security-descriptor control flags through `GetNamedSecurityInfoW`. It requests only owner, group, and DACL information; SACL and mandatory integrity labels are deferred because they require privilege-dependent access.

The returned descriptor buffer is owned by `SafeSecurityDescriptorHandle` and released with `LocalFree`; pointers to its owner, group, DACL, and ACEs are parsed only while that owner remains alive. A null DACL (permits all access), an empty DACL (permits none), and an absent DACL are represented separately. Control flags retain their raw bits, including DACL-present/defaulted, automatic-inheritance, and protection state.

ACL inspection is not effective-access evaluation: **ACL != effective access**, and **Allow ACE != guaranteed access**. Windows compares access-token user/group SIDs with ACE SIDs and also considers deny ACEs, requested access, inheritance, privileges, integrity policy, and other rules. This lab does not call `AccessCheck`, modify ACLs, tokens, or privileges.
