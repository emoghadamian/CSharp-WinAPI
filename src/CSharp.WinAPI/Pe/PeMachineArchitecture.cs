namespace CSharp.WinAPI.Pe;

/// <summary>Classifies common IMAGE_FILE_HEADER machine values without discarding the original raw value.</summary>
public enum PeMachineArchitecture
{
    /// <summary>The machine value is not one of the classifications exposed by this library.</summary>
    Unknown,

    /// <summary>Intel 386 or compatible architecture.</summary>
    I386,

    /// <summary>AMD64/x64 architecture.</summary>
    Amd64,

    /// <summary>ARM64 architecture.</summary>
    Arm64,
}
