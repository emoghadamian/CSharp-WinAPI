using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Advapi32;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Security;

/// <summary>Evaluates the current process token against a file or directory security descriptor without modifying either.</summary>
public sealed class AccessCheckInspector
{
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorInvalidParameter = 87;
    private const int MaximumPrivilegeSetLength = 64 * 1024;
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
        using var primaryToken = OpenCurrentProcessToken(descriptor.Path);
        using var clientToken = DuplicateForAccessCheck(primaryToken, descriptor.Path);
        var mappedAccess = desiredAccess;
        Advapi32Native.MapGenericMask(ref mappedAccess, in FileMapping);
        return InvokeAccessCheck(descriptor, clientToken, desiredAccess, mappedAccess);
    }

    private static SafeTokenHandle OpenCurrentProcessToken(string path)
    {
        if (Advapi32Native.OpenProcessToken(Kernel32Native.GetCurrentProcess(), TokenAccessRights.Query | TokenAccessRights.Duplicate, out var token)) return token;
        token.Dispose();
        throw LastError(nameof(Advapi32Native.OpenProcessToken), path);
    }

    private static SafeTokenHandle DuplicateForAccessCheck(SafeTokenHandle primaryToken, string path)
    {
        if (Advapi32Native.DuplicateToken(primaryToken, SecurityImpersonationLevel.Impersonation, out var duplicate)) return duplicate;
        duplicate.Dispose();
        throw LastError(nameof(Advapi32Native.DuplicateToken), path);
    }

    private static EffectiveAccessResult InvokeAccessCheck(SecurityDescriptorLease descriptor, SafeTokenHandle clientToken, uint desiredAccess, uint mappedAccess)
    {
        uint privilegeLength = 0;
        if (Advapi32Native.AccessCheck(descriptor.Pointer, clientToken, mappedAccess, in FileMapping, nint.Zero, ref privilegeLength, out var grantedAccess, out var accessStatus))
        {
            return new EffectiveAccessResult(desiredAccess, mappedAccess, grantedAccess, accessStatus, Array.Empty<PrivilegeUseInfo>());
        }

        var error = Marshal.GetLastPInvokeError();
        if (error != ErrorInsufficientBuffer || privilegeLength == 0 || privilegeLength > MaximumPrivilegeSetLength)
        {
            throw new AccessCheckInspectionException(nameof(Advapi32Native.AccessCheck), descriptor.Path, error);
        }

        var buffer = new byte[checked((int)privilegeLength)];
        unsafe
        {
            fixed (byte* bytes = buffer)
            {
                if (!Advapi32Native.AccessCheck(descriptor.Pointer, clientToken, mappedAccess, in FileMapping, (nint)bytes, ref privilegeLength, out grantedAccess, out accessStatus))
                {
                    throw LastError(nameof(Advapi32Native.AccessCheck), descriptor.Path);
                }
            }
        }

        return new EffectiveAccessResult(desiredAccess, mappedAccess, grantedAccess, accessStatus, ParsePrivileges(buffer, privilegeLength, descriptor.Path));
    }

    private static IReadOnlyList<PrivilegeUseInfo> ParsePrivileges(byte[] buffer, uint returnedLength, string path)
    {
        const int headerSize = 8;
        var length = checked((int)returnedLength);
        if (length < headerSize) throw new AccessCheckInspectionException("PRIVILEGE_SET", path, ErrorInvalidParameter);
        var count = BitConverter.ToUInt32(buffer, 0);
        var itemSize = Marshal.SizeOf<LuidAndAttributesNative>();
        if (count > 4096 || (ulong)headerSize + ((ulong)count * (uint)itemSize) > (uint)length) throw new AccessCheckInspectionException("PRIVILEGE_SET", path, ErrorInvalidParameter);
        var list = new List<PrivilegeUseInfo>((int)count);
        unsafe { fixed (byte* bytes = buffer) for (var index = 0U; index < count; index++) { var item = Marshal.PtrToStructure<LuidAndAttributesNative>((nint)(bytes + headerSize + ((int)index * itemSize))); list.Add(new PrivilegeUseInfo(item.Luid.ToUInt64(), item.Attributes)); } }
        return Array.AsReadOnly(list.ToArray());
    }

    private static AccessCheckInspectionException LastError(string operation, string path) => new(operation, path, Marshal.GetLastPInvokeError());
}
