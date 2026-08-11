namespace CSharp.WinAPI.Security;

/// <summary>Known security-descriptor control bits; unrecognized bits remain available through the raw value.</summary>
[Flags]
public enum SecurityDescriptorControlFlags : ushort
{
    /// <summary>The owner was supplied by a default mechanism.</summary>
    OwnerDefaulted = 0x0001,
    /// <summary>The group was supplied by a default mechanism.</summary>
    GroupDefaulted = 0x0002,
    /// <summary>The DACL was supplied by a default mechanism.</summary>
    DaclDefaulted = 0x0008,
    /// <summary>The DACL is present, which can still mean it is null.</summary>
    DaclPresent = 0x0004,
    /// <summary>The descriptor requested automatic DACL inheritance.</summary>
    DaclAutoInheritRequired = 0x0100,
    /// <summary>The DACL was automatically inherited.</summary>
    DaclAutoInherited = 0x0400,
    /// <summary>The DACL is protected from automatic inheritance.</summary>
    DaclProtected = 0x1000,
    /// <summary>The descriptor is self-relative.</summary>
    SelfRelative = 0x8000,
}
