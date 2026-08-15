namespace CSharp.WinAPI.Services;

/// <summary>Known SERVICE_ERROR_* values.</summary>
public enum ServiceErrorControl
{
    /// <summary>Unrecognized native value.</summary>
    Unknown,
    /// <summary>Ignore startup failure.</summary>
    Ignore,
    /// <summary>Log and continue on failure.</summary>
    Normal,
    /// <summary>Severe startup failure.</summary>
    Severe,
    /// <summary>Critical startup failure.</summary>
    Critical,
}
