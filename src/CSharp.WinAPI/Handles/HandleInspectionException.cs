#pragma warning disable CS1591
namespace CSharp.WinAPI.Handles;
/// <summary>Represents an NT native or malformed-data failure during handle metadata inspection.</summary>
public sealed class HandleInspectionException : Exception
{
    internal HandleInspectionException(string operation, int status, int? bufferSize = null) : base($"{operation} failed with NTSTATUS 0x{status:X8}{(bufferSize is null ? string.Empty : $" (buffer {bufferSize} bytes)")}") { Operation = operation; NtStatus = status; BufferSize = bufferSize; }
    internal HandleInspectionException(string operation, string message) : base($"{operation} failed: {message}") { Operation = operation; }
    /// <summary>Gets the failed operation.</summary>
    public string Operation { get; }
    /// <summary>Gets the original NTSTATUS when the native call failed.</summary>
    public int? NtStatus { get; }
    /// <summary>Gets the buffer size involved in a native failure, when applicable.</summary>
    public int? BufferSize { get; }
}
#pragma warning restore CS1591
