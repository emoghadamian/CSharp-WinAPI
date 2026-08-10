namespace CSharp.WinAPI.Pe;

/// <summary>Represents a validation or I/O failure while inspecting an untrusted PE image.</summary>
public sealed class PeImageInspectionException : Exception
{
    internal PeImageInspectionException(string? filePath, string stage, string reason, Exception? innerException = null)
        : base($"PE inspection failed at {stage} for '{filePath ?? "<unspecified>"}': {reason}", innerException)
    {
        FilePath = filePath;
        Stage = stage;
        Reason = reason;
    }

    /// <summary>Gets the path supplied for inspection, when available.</summary>
    public string? FilePath { get; }

    /// <summary>Gets the validation or I/O stage that failed.</summary>
    public string Stage { get; }

    /// <summary>Gets the safe, high-level reason for the failure.</summary>
    public string Reason { get; }
}
