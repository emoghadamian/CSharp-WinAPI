namespace CSharp.WinAPI.Pe;

/// <summary>Identifies the optional-header layout used by a PE image.</summary>
public enum PeImageFormat : ushort
{
    /// <summary>The PE32 optional-header layout.</summary>
    Pe32 = 0x010B,

    /// <summary>The PE32+ optional-header layout.</summary>
    Pe32Plus = 0x020B,
}
