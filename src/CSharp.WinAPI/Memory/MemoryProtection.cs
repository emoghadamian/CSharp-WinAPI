namespace CSharp.WinAPI.Memory;

/// <summary>Represents documented page-protection bases and modifiers reported by virtual-memory metadata.</summary>
[Flags]
public enum MemoryProtection : uint
{
    /// <summary>No protection value was reported.</summary>
    None = 0x00000000,

    /// <summary>Disables all access to committed pages.</summary>
    NoAccess = 0x00000001,

    /// <summary>Allows read-only access.</summary>
    ReadOnly = 0x00000002,

    /// <summary>Allows read and write access.</summary>
    ReadWrite = 0x00000004,

    /// <summary>Allows copy-on-write access to a mapped view.</summary>
    WriteCopy = 0x00000008,

    /// <summary>Allows execute-only access.</summary>
    Execute = 0x00000010,

    /// <summary>Allows execute and read access.</summary>
    ExecuteRead = 0x00000020,

    /// <summary>Allows execute, read, and write access.</summary>
    ExecuteReadWrite = 0x00000040,

    /// <summary>Allows execute copy-on-write access to a mapped view.</summary>
    ExecuteWriteCopy = 0x00000080,

    /// <summary>Marks pages as one-time guard pages.</summary>
    Guard = 0x00000100,

    /// <summary>Marks pages as non-cacheable.</summary>
    NoCache = 0x00000200,

    /// <summary>Marks pages as write-combined.</summary>
    WriteCombine = 0x00000400,

    /// <summary>Marks executable locations as invalid Control Flow Guard targets.</summary>
    TargetsInvalid = 0x40000000,
}
