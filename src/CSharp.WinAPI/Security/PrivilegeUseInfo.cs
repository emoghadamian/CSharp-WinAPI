namespace CSharp.WinAPI.Security;

/// <summary>A native LUID and attributes reported by AccessCheck's PRIVILEGE_SET.</summary>
public sealed record PrivilegeUseInfo(ulong Luid, uint Attributes);
