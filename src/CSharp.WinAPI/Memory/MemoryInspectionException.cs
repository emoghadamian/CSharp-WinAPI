using System.ComponentModel;

namespace CSharp.WinAPI.Memory;

/// <summary>Represents a Win32 error encountered while opening a process or querying its virtual-memory metadata.</summary>
public sealed class MemoryInspectionException : Win32Exception
{
    internal MemoryInspectionException(string operation, int errorCode)
        : base(errorCode, $"{operation} failed with Win32 error {errorCode}: {new Win32Exception(errorCode).Message}")
    {
        Operation = operation;
    }

    /// <summary>Gets the native operation that failed.</summary>
    public string Operation { get; }
}
