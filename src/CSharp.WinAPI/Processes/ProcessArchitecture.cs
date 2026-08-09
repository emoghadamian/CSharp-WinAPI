namespace CSharp.WinAPI.Processes;

/// <summary>Processor architecture derived from IMAGE_FILE_MACHINE values.</summary>
public enum ProcessArchitecture
{
    /// <summary>The machine type was unavailable or is not mapped by this library.</summary>
    Unknown,

    /// <summary>32-bit Intel-compatible architecture.</summary>
    X86,

    /// <summary>64-bit AMD/Intel-compatible architecture.</summary>
    X64,

    /// <summary>32-bit ARM architecture.</summary>
    Arm,

    /// <summary>64-bit ARM architecture.</summary>
    Arm64,

    /// <summary>Intel Itanium architecture.</summary>
    Itanium,
}
