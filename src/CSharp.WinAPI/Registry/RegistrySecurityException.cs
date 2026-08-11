using System.ComponentModel;
namespace CSharp.WinAPI.Registry;

/// <summary>Represents an LSTATUS failure while inspecting a local registry key.</summary>
public sealed class RegistrySecurityException : Win32Exception
{
    internal RegistrySecurityException(string operation, RegistryKeyPath path, int status)
        : base(status, $"{operation} failed for {path.Hive}\\{path.SubKey} ({path.View}) with LSTATUS {status}: {new Win32Exception(status).Message}")
    {
        Operation = operation;
        Path = path;
    }

    /// <summary>Gets the failed registry operation.</summary>
    public string Operation { get; }

    /// <summary>Gets the requested registry path.</summary>
    public RegistryKeyPath Path { get; }
}
