namespace CSharp.WinAPI.Security;

/// <summary>The completed native authorization decision; denial is a normal result, not an exception.</summary>
public sealed record EffectiveAccessResult(uint DesiredAccess, uint MappedDesiredAccess, uint GrantedAccess, bool IsGranted, IReadOnlyList<PrivilegeUseInfo> PrivilegesUsed)
{
    /// <summary>Gets an immutable snapshot of privileges reported by AccessCheck.</summary>
    public IReadOnlyList<PrivilegeUseInfo> PrivilegesUsed { get; } = Array.AsReadOnly(PrivilegesUsed.ToArray());
}
