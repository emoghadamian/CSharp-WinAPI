namespace CSharp.WinAPI.Memory;

/// <summary>Represents the state reported for a virtual-memory region.</summary>
public enum MemoryState : uint
{
    /// <summary>Pages have physical storage in memory or the paging file.</summary>
    Commit = 0x00001000,

    /// <summary>Pages are reserved without physical storage.</summary>
    Reserve = 0x00002000,

    /// <summary>Pages are unallocated and available for future allocation.</summary>
    Free = 0x00010000,
}
