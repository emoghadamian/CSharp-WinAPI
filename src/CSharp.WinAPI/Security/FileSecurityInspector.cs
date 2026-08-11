using System.Runtime.InteropServices;
using System.Security.Principal;
using CSharp.WinAPI.Interop.Advapi32;

namespace CSharp.WinAPI.Security;

/// <summary>Inspects file and directory security descriptors without modifying their security metadata.</summary>
public sealed class FileSecurityInspector
{
    private const int ErrorInvalidParameter = 87;
    private const int MaximumAceCount = 16_384;
    private const int MinimumAceSize = 8;
    private const byte AccessAllowedAceType = 0x00;
    private const byte AccessDeniedAceType = 0x01;
    private const byte SystemAuditAceType = 0x02;

    /// <summary>Reads owner, group, DACL, and control metadata for an existing file or directory.</summary>
    public FileSecurityInfo Inspect(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var targetPath = Path.GetFullPath(path);
        var status = Advapi32Native.GetNamedSecurityInfo(
            targetPath,
            SecurityObjectType.FileObject,
            SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl,
            out var owner,
            out var group,
            out var dacl,
            nint.Zero,
            out var descriptor);

        if (status != 0)
        {
            descriptor.Dispose();
            throw new FileSecurityInspectionException(nameof(Advapi32Native.GetNamedSecurityInfo), targetPath, unchecked((int)status));
        }

        using (descriptor)
        {
            var control = ReadControl(descriptor, targetPath);
            var parsedOwner = ReadDescriptorSid(descriptor, owner, isOwner: true, targetPath);
            var parsedGroup = ReadDescriptorSid(descriptor, group, isOwner: false, targetPath);
            var parsedDacl = ReadDacl(descriptor, dacl, targetPath);
            return new FileSecurityInfo(targetPath, parsedOwner, parsedGroup, parsedDacl, (SecurityDescriptorControlFlags)control.Flags, control.Revision);
        }
    }

    private static (ushort Flags, ushort Revision) ReadControl(SafeSecurityDescriptorHandle descriptor, string path)
    {
        if (!Advapi32Native.GetSecurityDescriptorControl(descriptor, out var flags, out var revision))
        {
            throw LastError(nameof(Advapi32Native.GetSecurityDescriptorControl), path);
        }

        if (revision > ushort.MaxValue)
        {
            throw new FileSecurityInspectionException(nameof(Advapi32Native.GetSecurityDescriptorControl), path, ErrorInvalidParameter);
        }

        return (flags, (ushort)revision);
    }

    private static SecurityIdentifierInfo? ReadDescriptorSid(SafeSecurityDescriptorHandle descriptor, nint sid, bool isOwner, string path)
    {
        var succeeded = isOwner
            ? Advapi32Native.GetSecurityDescriptorOwner(descriptor, out var returnedSid, out _)
            : Advapi32Native.GetSecurityDescriptorGroup(descriptor, out returnedSid, out _);

        if (!succeeded)
        {
            throw LastError(isOwner ? nameof(Advapi32Native.GetSecurityDescriptorOwner) : nameof(Advapi32Native.GetSecurityDescriptorGroup), path);
        }

        if (returnedSid != sid)
        {
            throw new FileSecurityInspectionException("Security descriptor SID", path, ErrorInvalidParameter);
        }

        return sid == nint.Zero ? null : ReadSid(sid, "Security descriptor SID", path);
    }

    private static DiscretionaryAclInfo ReadDacl(SafeSecurityDescriptorHandle descriptor, nint expectedDacl, string path)
    {
        if (!Advapi32Native.GetSecurityDescriptorDacl(descriptor, out var present, out var dacl, out _))
        {
            throw LastError(nameof(Advapi32Native.GetSecurityDescriptorDacl), path);
        }

        if (present && dacl != expectedDacl)
        {
            throw new FileSecurityInspectionException(nameof(Advapi32Native.GetSecurityDescriptorDacl), path, ErrorInvalidParameter);
        }

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
            throw new FileSecurityInspectionException("DACL header", path, ErrorInvalidParameter);
        }

        if (!Advapi32Native.GetAclInformation(dacl, out var sizeInformation, (uint)Marshal.SizeOf<AclSizeInformationNative>(), AclInformationClass.AclSizeInformation) ||
            sizeInformation.AceCount != header.AceCount || sizeInformation.AclBytesInUse < Marshal.SizeOf<AclNative>() || sizeInformation.AclBytesInUse > header.Size)
        {
            throw LastError(nameof(Advapi32Native.GetAclInformation), path);
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

        return new DiscretionaryAclInfo(true, false, header.AceCount == 0, entries);
    }

    private static AccessControlEntryInfo ParseAce(nint ace, nuint aclStart, nuint aclEnd, string path)
    {
        var aceAddress = (nuint)ace;
        if (ace == nint.Zero || aceAddress < aclStart || aceAddress > aclEnd - (nuint)Marshal.SizeOf<AceHeaderNative>())
        {
            throw new FileSecurityInspectionException("ACE pointer", path, ErrorInvalidParameter);
        }

        var header = Marshal.PtrToStructure<AceHeaderNative>(ace);
        if (header.Size < MinimumAceSize || (header.Size & 3) != 0 || header.Size > aclEnd - aceAddress)
        {
            throw new FileSecurityInspectionException("ACE size", path, ErrorInvalidParameter);
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
            throw new FileSecurityInspectionException("ACE SID", path, ErrorInvalidParameter);
        }

        var sid = ace + sidOffset;
        var trustee = ReadSidWithinAce(sid, header.Size - sidOffset, path);
        return new AccessControlEntryInfo(header.Type, type, (AccessControlEntryFlags)header.Flags, accessMask, trustee);
    }

    private static SecurityIdentifierInfo ReadSidWithinAce(nint sid, int availableBytes, string path)
    {
        if (sid == nint.Zero || !Advapi32Native.IsValidSid(sid))
        {
            throw new FileSecurityInspectionException("ACE SID", path, ErrorInvalidParameter);
        }

        var sidString = ConvertSid(sid, path);
        var sidLength = new SecurityIdentifier(sidString).BinaryLength;
        if (sidLength > availableBytes)
        {
            throw new FileSecurityInspectionException("ACE SID", path, ErrorInvalidParameter);
        }

        return new SecurityIdentifierInfo(sidString, TryResolveAccountName(sidString));
    }

    private static SecurityIdentifierInfo ReadSid(nint sid, string operation, string path)
    {
        if (!Advapi32Native.IsValidSid(sid))
        {
            throw new FileSecurityInspectionException(operation, path, ErrorInvalidParameter);
        }

        var sidString = ConvertSid(sid, path);
        return new SecurityIdentifierInfo(sidString, TryResolveAccountName(sidString));
    }

    private static string ConvertSid(nint sid, string path)
    {
        if (!Advapi32Native.ConvertSidToStringSid(sid, out var stringSid))
        {
            throw LastError(nameof(Advapi32Native.ConvertSidToStringSid), path);
        }

        try
        {
            return Marshal.PtrToStringUni(stringSid) ?? throw new FileSecurityInspectionException(nameof(Advapi32Native.ConvertSidToStringSid), path, ErrorInvalidParameter);
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

    private static FileSecurityInspectionException LastError(string operation, string path) =>
        new(operation, path, Marshal.GetLastPInvokeError());
}
