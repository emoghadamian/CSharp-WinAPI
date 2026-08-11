using CSharp.WinAPI.Interop.Advapi32;

namespace CSharp.WinAPI.Security;

/// <summary>Evaluates the current process token against a file or directory security descriptor without modifying either.</summary>
public sealed class AccessCheckInspector
{
    private static readonly GenericMappingNative FileMapping = new()
    {
        GenericRead = 0x00120089,
        GenericWrite = 0x00120116,
        GenericExecute = 0x001200A0,
        GenericAll = 0x001F01FF,
    };

    /// <summary>Evaluates desired file-system access for a temporary duplicate of the current process token.</summary>
    public EffectiveAccessResult EvaluatePathAccess(string path, uint desiredAccess)
    {
        using var descriptor = SecurityDescriptorLease.Open(path);
        return AccessCheckEvaluator.Evaluate(descriptor.Pointer, descriptor.Path, in FileMapping, desiredAccess);
    }
}
