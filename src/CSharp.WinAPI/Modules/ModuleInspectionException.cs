using System.ComponentModel;

namespace CSharp.WinAPI.Modules;

/// <summary>Represents a Win32 error encountered while taking or enumerating a Toolhelp32 module snapshot.</summary>
public sealed class ModuleInspectionException : Win32Exception
{
    internal ModuleInspectionException(string operation, int errorCode)
        : base(errorCode, $"{operation} failed with Win32 error {errorCode}: {new Win32Exception(errorCode).Message}")
    {
        Operation = operation;
    }

    /// <summary>The native operation that failed.</summary>
    public string Operation { get; }
}
