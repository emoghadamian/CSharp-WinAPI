namespace CSharp.WinAPI.Etw;

/// <summary>Represents a TDH provider-enumeration or metadata-validation failure.</summary>
public sealed class EtwProviderInspectionException : Exception
{
    internal EtwProviderInspectionException(string operation, uint nativeErrorCode)
        : base($"{operation} failed with TDH status {nativeErrorCode}: {new System.ComponentModel.Win32Exception((int)nativeErrorCode).Message}")
    {
        Operation = operation;
        NativeErrorCode = nativeErrorCode;
    }

    internal EtwProviderInspectionException(string operation, string message)
        : base($"{operation} failed: {message}") => Operation = operation;

    /// <summary>Gets the failed TDH operation or validation step.</summary>
    public string Operation { get; }

    /// <summary>Gets the TDH/Win32 status value when the failure originated with TDH.</summary>
    public uint? NativeErrorCode { get; }
}
