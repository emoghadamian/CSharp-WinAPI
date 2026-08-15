namespace CSharp.WinAPI.Pipes;

/// <summary>Represents a native named-pipe enumeration or validation failure.</summary>
public sealed class NamedPipeInspectionException : Exception
{
    internal NamedPipeInspectionException(string operation, int error)
        : base($"{operation} failed with Win32 error {error}: {new System.ComponentModel.Win32Exception(error).Message}")
    {
        Operation = operation;
        NativeErrorCode = error;
    }

    internal NamedPipeInspectionException(string operation, string message)
        : base($"{operation} failed: {message}") => Operation = operation;

    /// <summary>Gets the failed native operation or validation step.</summary>
    public string Operation { get; }

    /// <summary>Gets the native error code when the failure originated with Win32.</summary>
    public int? NativeErrorCode { get; }
}
