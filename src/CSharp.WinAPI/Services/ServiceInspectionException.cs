using System.ComponentModel;

namespace CSharp.WinAPI.Services;

/// <summary>Represents a Win32 failure while enumerating services or querying a service configuration.</summary>
public sealed class ServiceInspectionException : Win32Exception
{
    internal ServiceInspectionException(string operation, string? serviceName, int errorCode)
        : base(errorCode, $"{operation} failed{(serviceName is null ? string.Empty : $" for service '{serviceName}'")} with Win32 error {errorCode}: {new Win32Exception(errorCode).Message}")
    {
        Operation = operation;
        ServiceName = serviceName;
    }

    /// <summary>Gets the failed native operation.</summary>
    public string Operation { get; }

    /// <summary>Gets the service identity when one was involved in the operation.</summary>
    public string? ServiceName { get; }
}
