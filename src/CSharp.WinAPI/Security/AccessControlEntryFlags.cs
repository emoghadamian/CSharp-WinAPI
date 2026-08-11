namespace CSharp.WinAPI.Security;

/// <summary>ACE inheritance and audit flags; raw bits remain available through the public enum value.</summary>
[Flags]
public enum AccessControlEntryFlags : byte
{
    /// <summary>Non-container child objects inherit the ACE.</summary>
    ObjectInherit = 0x01,
    /// <summary>Container child objects inherit the ACE.</summary>
    ContainerInherit = 0x02,
    /// <summary>Inheritance does not propagate beyond one generation.</summary>
    NoPropagateInherit = 0x04,
    /// <summary>The ACE applies only to inherited child objects.</summary>
    InheritOnly = 0x08,
    /// <summary>The ACE applies to successful access auditing.</summary>
    SuccessfulAccess = 0x40,
    /// <summary>The ACE applies to failed access auditing.</summary>
    FailedAccess = 0x80,
    /// <summary>The ACE was inherited from a parent object.</summary>
    Inherited = 0x10,
}
