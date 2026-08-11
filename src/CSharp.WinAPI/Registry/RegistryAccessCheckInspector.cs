using CSharp.WinAPI.Interop.Advapi32;
using CSharp.WinAPI.Security;

namespace CSharp.WinAPI.Registry;

/// <summary>Evaluates the current process token against a local registry-key security descriptor without modifying the key.</summary>
public sealed class RegistryAccessCheckInspector
{
    private static readonly GenericMappingNative RegistryMapping = new()
    {
        GenericRead = 0x00020019,
        GenericWrite = 0x00020006,
        GenericExecute = 0x00020019,
        GenericAll = 0x000F003F,
    };

    /// <summary>Evaluates desired registry-key access for a temporary duplicate of the current process token.</summary>
    public EffectiveAccessResult EvaluateCurrentProcessKeyAccess(RegistryKeyPath path, uint desiredAccess)
    {
        ArgumentNullException.ThrowIfNull(path);
        using var descriptor = RegistrySecurityDescriptorLease.Open(path);
        return AccessCheckEvaluator.Evaluate(descriptor.Pointer, FormatPath(path), in RegistryMapping, desiredAccess);
    }

    private static string FormatPath(RegistryKeyPath path) => $"{path.Hive}\\{path.SubKey} ({path.View})";
}
