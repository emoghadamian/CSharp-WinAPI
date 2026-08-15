using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Advapi32;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Security;

/// <summary>Internal, lifetime-scoped current-token bridge for native AccessCheck evaluation.</summary>
internal static class AccessCheckEvaluator
{
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorInvalidParameter = 87;
    private const int MaximumPrivilegeSetLength = 64 * 1024;

    internal static EffectiveAccessResult Evaluate(nint securityDescriptor, string objectLabel, in GenericMappingNative mapping, uint desiredAccess)
    {
        using var primaryToken = OpenCurrentProcessToken(objectLabel);
        using var clientToken = DuplicateForAccessCheck(primaryToken, objectLabel);

        var mappedAccess = desiredAccess;
        Advapi32Native.MapGenericMask(ref mappedAccess, in mapping);
        return InvokeAccessCheck(securityDescriptor, clientToken, objectLabel, in mapping, desiredAccess, mappedAccess);
    }

    private static SafeTokenHandle OpenCurrentProcessToken(string objectLabel)
    {
        if (Advapi32Native.OpenProcessToken(Kernel32Native.GetCurrentProcess(), TokenAccessRights.Query | TokenAccessRights.Duplicate, out var token))
        {
            return token;
        }

        token.Dispose();
        throw LastError(nameof(Advapi32Native.OpenProcessToken), objectLabel);
    }

    private static SafeTokenHandle DuplicateForAccessCheck(SafeTokenHandle primaryToken, string objectLabel)
    {
        if (Advapi32Native.DuplicateToken(primaryToken, SecurityImpersonationLevel.Impersonation, out var duplicate))
        {
            return duplicate;
        }

        duplicate.Dispose();
        throw LastError(nameof(Advapi32Native.DuplicateToken), objectLabel);
    }

    private static EffectiveAccessResult InvokeAccessCheck(
        nint securityDescriptor,
        SafeTokenHandle clientToken,
        string objectLabel,
        in GenericMappingNative mapping,
        uint desiredAccess,
        uint mappedAccess)
    {
        uint privilegeLength = 0;
        if (Advapi32Native.AccessCheck(securityDescriptor, clientToken, mappedAccess, in mapping, nint.Zero, ref privilegeLength, out var grantedAccess, out var accessStatus))
        {
            return new EffectiveAccessResult(desiredAccess, mappedAccess, grantedAccess, accessStatus, Array.Empty<PrivilegeUseInfo>());
        }

        var error = Marshal.GetLastPInvokeError();
        if (error != ErrorInsufficientBuffer || privilegeLength == 0 || privilegeLength > MaximumPrivilegeSetLength)
        {
            throw new AccessCheckInspectionException(nameof(Advapi32Native.AccessCheck), objectLabel, error);
        }

        var buffer = new byte[checked((int)privilegeLength)];
        unsafe
        {
            fixed (byte* bytes = buffer)
            {
                if (!Advapi32Native.AccessCheck(securityDescriptor, clientToken, mappedAccess, in mapping, (nint)bytes, ref privilegeLength, out grantedAccess, out accessStatus))
                {
                    throw LastError(nameof(Advapi32Native.AccessCheck), objectLabel);
                }
            }
        }

        return new EffectiveAccessResult(desiredAccess, mappedAccess, grantedAccess, accessStatus, ParsePrivileges(buffer, privilegeLength, objectLabel));
    }

    private static IReadOnlyList<PrivilegeUseInfo> ParsePrivileges(byte[] buffer, uint returnedLength, string objectLabel)
    {
        const int HeaderSize = 8;
        var length = checked((int)returnedLength);
        if (length < HeaderSize)
        {
            throw new AccessCheckInspectionException("PRIVILEGE_SET", objectLabel, ErrorInvalidParameter);
        }

        // PRIVILEGE_SET begins with a DWORD Control followed by DWORD PrivilegeCount.
        var count = BitConverter.ToUInt32(buffer, sizeof(uint));
        var itemSize = Marshal.SizeOf<LuidAndAttributesNative>();
        if (count > 4096 || (ulong)HeaderSize + ((ulong)count * (uint)itemSize) > (uint)length)
        {
            throw new AccessCheckInspectionException("PRIVILEGE_SET", objectLabel, ErrorInvalidParameter);
        }

        var privileges = new List<PrivilegeUseInfo>((int)count);
        unsafe
        {
            fixed (byte* bytes = buffer)
            {
                for (var index = 0U; index < count; index++)
                {
                    var item = Marshal.PtrToStructure<LuidAndAttributesNative>((nint)(bytes + HeaderSize + ((int)index * itemSize)));
                    privileges.Add(new PrivilegeUseInfo(item.Luid.ToUInt64(), item.Attributes));
                }
            }
        }

        return Array.AsReadOnly(privileges.ToArray());
    }

    private static AccessCheckInspectionException LastError(string operation, string objectLabel) =>
        new(operation, objectLabel, Marshal.GetLastPInvokeError());
}
