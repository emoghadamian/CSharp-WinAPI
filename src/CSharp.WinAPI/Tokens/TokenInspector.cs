using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Principal;
using CSharp.WinAPI.Interop.Advapi32;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Tokens;

/// <summary>Provides read-only access-token inspection through OpenProcessToken and GetTokenInformation.</summary>
public sealed class TokenInspector
{
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorBadLength = 24;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorNoSuchPrivilege = 1313;
    private const int MaximumTokenInformationLength = 16 * 1024 * 1024;
    private const int MaximumTokenGroupCount = 16_384;
    private const int MaximumTokenPrivilegeCount = 16_384;
    private const int MaximumPrivilegeNameLength = 1_024;

    /// <summary>Inspects the current process primary token without modifying it.</summary>
    public TokenInfo InspectCurrentProcessToken() => InspectProcessToken((uint)Environment.ProcessId);

    /// <summary>Inspects a process primary token using PROCESS_QUERY_LIMITED_INFORMATION and TOKEN_QUERY only.</summary>
    /// <exception cref="TokenInspectionException">Thrown when the process or token cannot be queried.</exception>
    public TokenInfo InspectProcessToken(uint processId)
    {
        using var process = Kernel32Native.OpenProcess(ProcessAccessRights.QueryLimitedInformation, inheritHandle: false, processId);

        if (process.IsInvalid)
        {
            throw CreateLastErrorException(nameof(Kernel32Native.OpenProcess), processId);
        }

        using var token = OpenToken(process, processId);
        using var userBuffer = QueryInformation(token, TokenInformationClass.User, processId);
        using var groupsBuffer = QueryInformation(token, TokenInformationClass.Groups, processId);
        using var privilegesBuffer = QueryInformation(token, TokenInformationClass.Privileges, processId);
        using var elevationBuffer = QueryInformation(token, TokenInformationClass.Elevation, processId);
        using var integrityBuffer = QueryInformation(token, TokenInformationClass.IntegrityLevel, processId);
        using var sessionBuffer = QueryInformation(token, TokenInformationClass.SessionId, processId);
        using var typeBuffer = QueryInformation(token, TokenInformationClass.Type, processId);
        var type = ParseTokenType(typeBuffer, processId);
        var impersonationLevel = type.Value == TokenType.Impersonation ? QueryImpersonationLevel(token, processId) : null;

        return new TokenInfo(
            processId,
            ParseUser(userBuffer, processId),
            ParseGroups(groupsBuffer, processId),
            ParsePrivileges(privilegesBuffer, processId),
            ParseElevation(elevationBuffer, processId),
            ParseIntegrityLevel(integrityBuffer, processId),
            ReadUInt32(sessionBuffer, "TokenSessionId", processId),
            type,
            impersonationLevel);
    }

    private static SafeTokenHandle OpenToken(SafeProcessHandle process, uint processId)
    {
        if (Advapi32Native.OpenProcessToken(process, TokenAccessRights.Query, out var token))
        {
            return token;
        }

        token.Dispose();
        throw CreateLastErrorException(nameof(Advapi32Native.OpenProcessToken), processId);
    }

    private static TokenBuffer QueryInformation(SafeTokenHandle token, TokenInformationClass informationClass, uint processId)
    {
        if (Advapi32Native.GetTokenInformation(token, informationClass, nint.Zero, 0, out var requiredLength))
        {
            throw new TokenInspectionException(nameof(Advapi32Native.GetTokenInformation), processId, ErrorInvalidParameter);
        }

        var errorCode = Marshal.GetLastPInvokeError();

        // Most information classes report ERROR_INSUFFICIENT_BUFFER. Some Windows
        // builds report ERROR_BAD_LENGTH for fixed-size token information while still
        // returning the required byte count, which is equally safe to honor here.
        if (errorCode is not (ErrorInsufficientBuffer or ErrorBadLength) || requiredLength == 0 || requiredLength > MaximumTokenInformationLength)
        {
            throw new TokenInspectionException($"{nameof(Advapi32Native.GetTokenInformation)}({informationClass})", processId, errorCode);
        }

        var bytes = new byte[checked((int)requiredLength)];

        unsafe
        {
            fixed (byte* buffer = bytes)
            {
                if (!Advapi32Native.GetTokenInformation(token, informationClass, (nint)buffer, requiredLength, out var returnedLength))
                {
                    throw CreateLastErrorException($"{nameof(Advapi32Native.GetTokenInformation)}({informationClass})", processId);
                }

                if (returnedLength == 0 || returnedLength > requiredLength)
                {
                    throw new TokenInspectionException($"{nameof(Advapi32Native.GetTokenInformation)}({informationClass})", processId, ErrorInvalidParameter);
                }

                return new TokenBuffer(bytes, returnedLength);
            }
        }
    }

    private static TokenUserInfo ParseUser(TokenBuffer buffer, uint processId)
    {
        var user = ReadStructure<TokenUserNative>(buffer, 0, "TokenUser", processId);
        var sid = ReadSid(buffer, user.User.Sid, "TokenUser", processId);
        return new TokenUserInfo(sid, TryResolveAccountName(sid));
    }

    private static IReadOnlyList<TokenGroupInfo> ParseGroups(TokenBuffer buffer, uint processId)
    {
        var count = ReadUInt32(buffer, "TokenGroups", processId);

        if (count > MaximumTokenGroupCount)
        {
            throw new TokenInspectionException("TokenGroups", processId, ErrorInvalidParameter);
        }

        var firstOffset = checked((int)Marshal.OffsetOf<TokenGroupsNative>(nameof(TokenGroupsNative.FirstGroup)));
        var itemSize = Marshal.SizeOf<SidAndAttributesNative>();
        RequireArrayRange(buffer, firstOffset, count, itemSize, "TokenGroups", processId);
        var groups = new List<TokenGroupInfo>((int)count);

        for (var index = 0U; index < count; index++)
        {
            var item = ReadStructure<SidAndAttributesNative>(buffer, checked(firstOffset + ((int)index * itemSize)), "TokenGroups", processId);
            groups.Add(new TokenGroupInfo(ReadSid(buffer, item.Sid, "TokenGroups", processId), (TokenGroupAttributes)item.Attributes));
        }

        return Array.AsReadOnly(groups.ToArray());
    }

    private static IReadOnlyList<TokenPrivilegeInfo> ParsePrivileges(TokenBuffer buffer, uint processId)
    {
        var count = ReadUInt32(buffer, "TokenPrivileges", processId);

        if (count > MaximumTokenPrivilegeCount)
        {
            throw new TokenInspectionException("TokenPrivileges", processId, ErrorInvalidParameter);
        }

        var firstOffset = checked((int)Marshal.OffsetOf<TokenPrivilegesNative>(nameof(TokenPrivilegesNative.FirstPrivilege)));
        var itemSize = Marshal.SizeOf<LuidAndAttributesNative>();
        RequireArrayRange(buffer, firstOffset, count, itemSize, "TokenPrivileges", processId);
        var privileges = new List<TokenPrivilegeInfo>((int)count);

        for (var index = 0U; index < count; index++)
        {
            var item = ReadStructure<LuidAndAttributesNative>(buffer, checked(firstOffset + ((int)index * itemSize)), "TokenPrivileges", processId);
            privileges.Add(new TokenPrivilegeInfo(item.Luid.ToUInt64(), TryLookupPrivilegeName(item.Luid), (TokenPrivilegeAttributes)item.Attributes));
        }

        return Array.AsReadOnly(privileges.ToArray());
    }

    private static bool ParseElevation(TokenBuffer buffer, uint processId) => ReadUInt32(buffer, "TokenElevation", processId) != 0;

    private static TokenIntegrityLevelInfo ParseIntegrityLevel(TokenBuffer buffer, uint processId)
    {
        var label = ReadStructure<TokenMandatoryLabelNative>(buffer, 0, "TokenIntegrityLevel", processId);
        var sid = ReadSid(buffer, label.Label.Sid, "TokenIntegrityLevel", processId);
        var identifier = new SecurityIdentifier(sid);
        var rid = identifier.Value.Split('-').LastOrDefault() is { } ridText && uint.TryParse(ridText, out var parsedRid) ? parsedRid : 0U;
        return new TokenIntegrityLevelInfo(sid, rid, MapIntegrityLevel(rid));
    }

    private static TokenTypeInfo ParseTokenType(TokenBuffer buffer, uint processId)
    {
        var rawValue = ReadUInt32(buffer, "TokenType", processId);
        return new TokenTypeInfo(rawValue, rawValue switch
        {
            1 => TokenType.Primary,
            2 => TokenType.Impersonation,
            _ => TokenType.Unknown,
        });
    }

    private static TokenImpersonationLevelInfo? QueryImpersonationLevel(SafeTokenHandle token, uint processId)
    {
        using var buffer = QueryInformation(token, TokenInformationClass.ImpersonationLevel, processId);
        var rawValue = ReadUInt32(buffer, "TokenImpersonationLevel", processId);
        return new TokenImpersonationLevelInfo(rawValue, rawValue switch
        {
            0 => TokenImpersonationLevel.Anonymous,
            1 => TokenImpersonationLevel.Identification,
            2 => TokenImpersonationLevel.Impersonation,
            3 => TokenImpersonationLevel.Delegation,
            _ => TokenImpersonationLevel.Unknown,
        });
    }

    private static TokenIntegrityLevel MapIntegrityLevel(uint rid) => rid switch
    {
        0x0000 => TokenIntegrityLevel.Untrusted,
        0x1000 => TokenIntegrityLevel.Low,
        0x2000 => TokenIntegrityLevel.Medium,
        0x2100 => TokenIntegrityLevel.MediumPlus,
        0x3000 => TokenIntegrityLevel.High,
        0x4000 => TokenIntegrityLevel.System,
        0x5000 => TokenIntegrityLevel.Protected,
        _ => TokenIntegrityLevel.Unknown,
    };

    private static string ReadSid(TokenBuffer buffer, nint sid, string operation, uint processId)
    {
        var bufferStart = (nuint)buffer.Pointer;
        var bufferEnd = checked(bufferStart + buffer.Length);
        var sidAddress = (nuint)sid;

        if (sid == nint.Zero || sidAddress < bufferStart || sidAddress >= bufferEnd || !Advapi32Native.IsValidSid(sid))
        {
            throw new TokenInspectionException(operation, processId, ErrorInvalidParameter);
        }

        var sidLength = Advapi32Native.GetLengthSid(sid);

        if (sidLength == 0 || sidLength > bufferEnd - sidAddress)
        {
            throw new TokenInspectionException(operation, processId, ErrorInvalidParameter);
        }

        return new SecurityIdentifier(sid).Value;
    }

    private static string? TryResolveAccountName(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch (IdentityNotMappedException)
        {
            return null;
        }
        catch (SystemException)
        {
            return null;
        }
    }

    private static unsafe string? TryLookupPrivilegeName(LuidNative luid)
    {
        uint requiredLength = 0;

        if (Advapi32Native.LookupPrivilegeName(null, in luid, null, ref requiredLength))
        {
            return string.Empty;
        }

        var errorCode = Marshal.GetLastPInvokeError();

        if (errorCode is ErrorNoSuchPrivilege or ErrorInvalidParameter ||
            errorCode == ErrorInsufficientBuffer && requiredLength == 0 ||
            requiredLength > MaximumPrivilegeNameLength)
        {
            return null;
        }

        var buffer = new char[checked((int)requiredLength + 1)];

        fixed (char* name = buffer)
        {
            var length = (uint)buffer.Length;

            if (!Advapi32Native.LookupPrivilegeName(null, in luid, name, ref length))
            {
                return null;
            }

            return new string(buffer, 0, checked((int)length));
        }
    }

    private static uint ReadUInt32(TokenBuffer buffer, string operation, uint processId)
    {
        if (buffer.Length < sizeof(uint))
        {
            throw new TokenInspectionException(operation, processId, ErrorInvalidParameter);
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(buffer.Bytes);
    }

    private static T ReadStructure<T>(TokenBuffer buffer, int offset, string operation, uint processId)
        where T : struct
    {
        var size = Marshal.SizeOf<T>();

        var returnedLength = checked((int)buffer.Length);

        if (offset < 0 || offset > returnedLength - size)
        {
            throw new TokenInspectionException(operation, processId, ErrorInvalidParameter);
        }

        return Marshal.PtrToStructure<T>(buffer.Pointer + offset);
    }

    private static void RequireArrayRange(TokenBuffer buffer, int offset, uint count, int itemSize, string operation, uint processId)
    {
        var requiredLength = (ulong)offset + ((ulong)count * (uint)itemSize);

        if (requiredLength > buffer.Length)
        {
            throw new TokenInspectionException(operation, processId, ErrorInvalidParameter);
        }
    }

    private static TokenInspectionException CreateLastErrorException(string operation, uint processId) =>
        new(operation, processId, Marshal.GetLastPInvokeError());

    private sealed class TokenBuffer : IDisposable
    {
        private GCHandle _pin;

        internal TokenBuffer(byte[] bytes, uint length)
        {
            Bytes = bytes;
            Length = length;
            _pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        }

        internal byte[] Bytes { get; }

        internal uint Length { get; }

        internal nint Pointer => _pin.AddrOfPinnedObject();

        public void Dispose()
        {
            if (_pin.IsAllocated)
            {
                _pin.Free();
            }
        }
    }
}
