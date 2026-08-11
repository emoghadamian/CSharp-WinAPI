using System.ComponentModel;
namespace CSharp.WinAPI.Security;
/// <summary>Represents a genuine native AccessCheck or token-acquisition failure.</summary>
public sealed class AccessCheckInspectionException : Win32Exception
{
    internal AccessCheckInspectionException(string operation, string path, int errorCode)
        : base(errorCode, $"{operation} failed for '{path}' with Win32 error {errorCode}: {new Win32Exception(errorCode).Message}")
    {
        this.Operation = operation;
        this.Path = path;
    }

    /// <summary>Gets the failed operation.</summary>
    public string Operation { get; }

    /// <summary>Gets the evaluated path.</summary>
    public string Path { get; }
}
