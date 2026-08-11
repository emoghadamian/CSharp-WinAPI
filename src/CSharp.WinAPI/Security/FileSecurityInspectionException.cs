using System.ComponentModel;

namespace CSharp.WinAPI.Security;

/// <summary>Represents a native failure while inspecting a file-system security descriptor.</summary>
public sealed class FileSecurityInspectionException : Win32Exception
{
    internal FileSecurityInspectionException(string operation, string path, int errorCode)
        : base(errorCode, $"{operation} failed for '{path}' with Win32 error {errorCode}: {new Win32Exception(errorCode).Message}")
    {
        Operation = operation;
        Path = path;
    }

    /// <summary>Gets the native operation that failed.</summary>
    public string Operation { get; }

    /// <summary>Gets the path being inspected.</summary>
    public string Path { get; }
}
