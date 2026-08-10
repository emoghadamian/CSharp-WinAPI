namespace CSharp.WinAPI.Pe;

/// <summary>Common IMAGE_SECTION_HEADER characteristics preserved from an image file.</summary>
[Flags]
public enum PeSectionCharacteristics : uint
{
    /// <summary>Contains executable code.</summary>
    ContainsCode = 0x00000020,

    /// <summary>Contains initialized data.</summary>
    ContainsInitializedData = 0x00000040,

    /// <summary>Contains uninitialized data.</summary>
    ContainsUninitializedData = 0x00000080,

    /// <summary>Section can be executed when mapped.</summary>
    MemoryExecute = 0x20000000,

    /// <summary>Section can be read when mapped.</summary>
    MemoryRead = 0x40000000,

    /// <summary>Section can be written when mapped.</summary>
    MemoryWrite = 0x80000000,
}
