using System.Runtime.InteropServices;
using System.Security.Principal;
using CSharp.WinAPI.Interop.Advapi32;
using CSharp.WinAPI.Security;

namespace CSharp.WinAPI.Registry;

/// <summary>Inspects local registry-key owner, group, DACL, and ACE metadata without modifying the registry.</summary>
public sealed class RegistrySecurityInspector
{
    private const int ErrorInvalidParameter = 87;
    private const int MaximumAceCount = 16_384;
    private const int MinimumAceSize = 8;
    private const byte AccessAllowedAceType = 0x00;
    private const byte AccessDeniedAceType = 0x01;
    private const byte SystemAuditAceType = 0x02;

    /// <summary>Reads owner, group, DACL, and ACE metadata from an existing local registry subkey.</summary>
    public RegistrySecurityInfo Inspect(RegistryKeyPath path)
    {
        ArgumentNullException.ThrowIfNull(path);
        using var descriptor = RegistrySecurityDescriptorLease.Open(path);
        return Parse(descriptor.Pointer, path);
    }

    private static RegistrySecurityInfo Parse(nint descriptor, RegistryKeyPath path)
    {
        if (!Advapi32Native.GetSecurityDescriptorControl(descriptor, out var control, out var revision) || revision > ushort.MaxValue)
        {
            throw LastError(nameof(Advapi32Native.GetSecurityDescriptorControl), path);
        }

        if (!Advapi32Native.GetSecurityDescriptorOwner(descriptor, out var owner, out _))
        {
            throw LastError(nameof(Advapi32Native.GetSecurityDescriptorOwner), path);
        }

        if (!Advapi32Native.GetSecurityDescriptorGroup(descriptor, out var group, out _))
        {
            throw LastError(nameof(Advapi32Native.GetSecurityDescriptorGroup), path);
        }

        if (!Advapi32Native.GetSecurityDescriptorDacl(descriptor, out var daclPresent, out var dacl, out _))
        {
            throw LastError(nameof(Advapi32Native.GetSecurityDescriptorDacl), path);
        }

        return new RegistrySecurityInfo(
            path,
            ReadSid(owner, "Security descriptor owner", path),
            ReadSid(group, "Security descriptor group", path),
            ReadDacl(daclPresent, dacl, path),
            (SecurityDescriptorControlFlags)control,
            (ushort)revision);
    }

    private static DiscretionaryAclInfo ReadDacl(bool present, nint dacl, RegistryKeyPath path)
    {
        if (!present)
        {
            return new DiscretionaryAclInfo(false, false, false, Array.Empty<AccessControlEntryInfo>());
        }

        if (dacl == nint.Zero)
        {
            return new DiscretionaryAclInfo(true, true, false, Array.Empty<AccessControlEntryInfo>());
        }

        var header = Marshal.PtrToStructure<AclNative>(dacl);
        if (header.Revision is not (2 or 4) || header.Size < Marshal.SizeOf<AclNative>() || header.AceCount > MaximumAceCount)
        {
            throw new RegistrySecurityException("DACL header", path, ErrorInvalidParameter);
        }

        if (!Advapi32Native.GetAclInformation(dacl, out var sizeInformation, (uint)Marshal.SizeOf<AclSizeInformationNative>(), AclInformationClass.AclSizeInformation))
        {
            throw LastError(nameof(Advapi32Native.GetAclInformation), path);
        }

        if (sizeInformation.AceCount != header.AceCount ||
            sizeInformation.AclBytesInUse < Marshal.SizeOf<AclNative>() ||
            sizeInformation.AclBytesInUse > header.Size)
        {
            throw new RegistrySecurityException(nameof(Advapi32Native.GetAclInformation), path, ErrorInvalidParameter);
        }

        var entries = new List<AccessControlEntryInfo>((int)header.AceCount);
        var aclStart = (nuint)dacl;
        var aclEnd = checked(aclStart + header.Size);
        for (var index = 0U; index < header.AceCount; index++)
        {
            if (!Advapi32Native.GetAce(dacl, index, out var ace))
            {
                throw LastError($"{nameof(Advapi32Native.GetAce)}({index})", path);
            }

            entries.Add(ParseAce(ace, aclStart, aclEnd, path));
        }

        return new DiscretionaryAclInfo(true, false, header.AceCount == 0, Array.AsReadOnly(entries.ToArray()));
    }

    private static AccessControlEntryInfo ParseAce(nint ace, nuint aclStart, nuint aclEnd, RegistryKeyPath path)
    {
        var aceAddress = (nuint)ace;
        if (ace == nint.Zero || aceAddress < aclStart || aceAddress > aclEnd - (nuint)Marshal.SizeOf<AceHeaderNative>())
        {
            throw new RegistrySecurityException("ACE pointer", path, ErrorInvalidParameter);
        }

        var header = Marshal.PtrToStructure<AceHeaderNative>(ace);
        if (header.Size < MinimumAceSize || (header.Size & 3) != 0 || header.Size > aclEnd - aceAddress)
        {
            throw new RegistrySecurityException("ACE size", path, ErrorInvalidParameter);
        }

        var type = header.Type switch
        {
            AccessAllowedAceType => AccessControlEntryType.Allowed,
            AccessDeniedAceType => AccessControlEntryType.Denied,
            SystemAuditAceType => AccessControlEntryType.SystemAudit,
            _ => AccessControlEntryType.Unknown,
        };

        if (type == AccessControlEntryType.Unknown)
        {
            return new AccessControlEntryInfo(header.Type, type, (AccessControlEntryFlags)header.Flags, null, null);
        }

        var accessMask = unchecked((uint)Marshal.ReadInt32(ace, Marshal.SizeOf<AceHeaderNative>()));
        var sidOffset = Marshal.SizeOf<AceHeaderNative>() + sizeof(uint);
        if (header.Size <= sidOffset)
        {
            throw new RegistrySecurityException("ACE SID", path, ErrorInvalidParameter);
        }

        return new AccessControlEntryInfo(
            header.Type,
            type,
            (AccessControlEntryFlags)header.Flags,
            accessMask,
            ReadSidWithinAce(ace + sidOffset, header.Size - sidOffset, path));
    }

    private static SecurityIdentifierInfo ReadSidWithinAce(nint sid, int availableBytes, RegistryKeyPath path)
    {
        var result = ReadSid(sid, "ACE SID", path);
        if (result is null || new SecurityIdentifier(result.Sid).BinaryLength > availableBytes)
        {
            throw new RegistrySecurityException("ACE SID", path, ErrorInvalidParameter);
        }

        return result;
    }

    private static SecurityIdentifierInfo? ReadSid(nint sid, string operation, RegistryKeyPath path)
    {
        if (sid == nint.Zero)
        {
            return null;
        }

        if (!Advapi32Native.IsValidSid(sid))
        {
            throw new RegistrySecurityException(operation, path, ErrorInvalidParameter);
        }

        var value = ConvertSid(sid, path);
        return new SecurityIdentifierInfo(value, TryResolveAccountName(value));
    }

    private static string ConvertSid(nint sid, RegistryKeyPath path)
    {
        if (!Advapi32Native.ConvertSidToStringSid(sid, out var stringSid))
        {
            throw LastError(nameof(Advapi32Native.ConvertSidToStringSid), path);
        }

        try
        {
            return Marshal.PtrToStringUni(stringSid) ?? throw new RegistrySecurityException(nameof(Advapi32Native.ConvertSidToStringSid), path, ErrorInvalidParameter);
        }
        finally
        {
            _ = CSharp.WinAPI.Interop.Kernel32.Kernel32Native.LocalFree(stringSid);
        }
    }

    private static string? TryResolveAccountName(string sid)
    {
        try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
        catch (SystemException) { return null; }
    }

    private static RegistrySecurityException LastError(string operation, RegistryKeyPath path) =>
        new(operation, path, Marshal.GetLastPInvokeError());
}
