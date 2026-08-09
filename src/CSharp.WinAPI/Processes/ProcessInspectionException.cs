using System.ComponentModel;

namespace CSharp.WinAPI.Processes;

/// <summary>Represents a Win32 error encountered while enumerating or locating a process.</summary>
public sealed class ProcessInspectionException : Win32Exception
{
    internal ProcessInspectionException(string operation, int errorCode)
        : base(errorCode, $"{operation} failed with Win32 error {errorCode}: {new Win32Exception(errorCode).Message}")
    {
        Operation = operation;
    }

    /// <summary>The native operation that failed.</summary>
    public string Operation { get; }
}
