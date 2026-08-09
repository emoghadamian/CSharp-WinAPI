using System.ComponentModel;

namespace CSharp.WinAPI.LocalGroups;

/// <summary>Represents a NET_API_STATUS returned by a Netapi32 API.</summary>
public sealed class NetApiException : Win32Exception
{
    internal NetApiException(string operation, int errorCode)
        : base(errorCode, $"{operation} failed with NET_API_STATUS {errorCode}: {new Win32Exception(errorCode).Message}")
    {
        Operation = operation;
    }

    /// <summary>The native API operation that returned the status code.</summary>
    public string Operation { get; }
}
