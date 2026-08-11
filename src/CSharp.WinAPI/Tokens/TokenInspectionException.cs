using System.ComponentModel;

namespace CSharp.WinAPI.Tokens;

/// <summary>Represents a Win32 failure while inspecting a process access token.</summary>
public sealed class TokenInspectionException : Win32Exception
{
    internal TokenInspectionException(string operation, uint processId, int errorCode)
        : base(errorCode, $"{operation} failed for PID {processId} with Win32 error {errorCode}: {new Win32Exception(errorCode).Message}")
    {
        Operation = operation;
        ProcessId = processId;
    }

    /// <summary>Gets the native operation that failed.</summary>
    public string Operation { get; }

    /// <summary>Gets the process ID whose token was being inspected.</summary>
    public uint ProcessId { get; }
}
