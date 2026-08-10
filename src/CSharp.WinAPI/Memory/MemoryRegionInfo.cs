namespace CSharp.WinAPI.Memory;

/// <summary>Read-only metadata for one contiguous virtual-memory region in a process.</summary>
/// <param name="BaseAddress">Unsigned pointer-sized base address of the reported region.</param>
/// <param name="AllocationBase">Unsigned pointer-sized base address of the originating allocation, when defined.</param>
/// <param name="RegionSize">Size of the region in bytes.</param>
/// <param name="State">Allocation state of the region.</param>
/// <param name="Protection">Current page protection flags, when defined.</param>
/// <param name="AllocationProtection">Protection requested when the allocation was created, when available.</param>
/// <param name="Type">Backing type of the region, when defined.</param>
public sealed record MemoryRegionInfo(
    nuint BaseAddress,
    nuint AllocationBase,
    nuint RegionSize,
    MemoryState State,
    MemoryProtection Protection,
    MemoryProtection AllocationProtection,
    MemoryType Type)
{
    /// <summary>Gets the unmodified native state value.</summary>
    public uint RawState => (uint)State;

    /// <summary>Gets the unmodified native current-protection flags.</summary>
    public uint RawProtection => (uint)Protection;

    /// <summary>Gets the unmodified native allocation-protection flags.</summary>
    public uint RawAllocationProtection => (uint)AllocationProtection;

    /// <summary>Gets the unmodified native region-type value.</summary>
    public uint RawType => (uint)Type;
}
