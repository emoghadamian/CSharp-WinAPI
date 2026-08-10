namespace CSharp.WinAPI.Memory;

/// <summary>Represents the backing type reported for a virtual-memory region.</summary>
public enum MemoryType : uint
{
    /// <summary>No type value was reported, which is normal for free or reserved regions.</summary>
    None = 0x00000000,

    /// <summary>Pages are private to the process.</summary>
    Private = 0x00020000,

    /// <summary>Pages are mapped from a section.</summary>
    Mapped = 0x00040000,

    /// <summary>Pages are mapped from an executable image section.</summary>
    Image = 0x01000000,
}
