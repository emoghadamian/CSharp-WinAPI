using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Netapi32;

namespace CSharp.WinAPI.LocalGroups;

/// <summary>
/// Provides read-only local-group inspection through NetLocalGroupEnum and NetLocalGroupGetMembers.
/// </summary>
public sealed class LocalGroupInspector
{
    /// <summary>Enumerates the local security groups on the current computer.</summary>
    public IReadOnlyList<LocalGroupInfo> EnumerateLocalGroups()
    {
        var groups = new List<LocalGroupInfo>();
        nuint resumeHandle = 0;

        do
        {
            var status = NetApiNative.NetLocalGroupEnum(
                serverName: null,
                level: 0,
                buffer: out var buffer,
                preferredMaximumLength: NetApiNative.MaxPreferredLength,
                entriesRead: out var entriesRead,
                totalEntries: out _,
                resumeHandle: ref resumeHandle);

            using var bufferHandle = new NetApiBufferSafeHandle(buffer);
            ThrowUnlessSuccessOrMoreData(status, nameof(NetApiNative.NetLocalGroupEnum));

            for (var index = 0u; index < entriesRead; index++)
            {
                var entry = Marshal.PtrToStructure<LocalGroupInfo0Native>(OffsetOf<LocalGroupInfo0Native>(buffer, index));
                var name = Marshal.PtrToStringUni(entry.Name);

                if (!string.IsNullOrWhiteSpace(name))
                {
                    groups.Add(new LocalGroupInfo(name));
                }
            }

            if (status == NetApiNative.NerrSuccess)
            {
                return groups;
            }
        }
        while (true);
    }

    /// <summary>Enumerates the accounts belonging to a named local security group.</summary>
    public IReadOnlyList<LocalGroupMemberInfo> EnumerateMembers(string localGroupName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(localGroupName);

        var members = new List<LocalGroupMemberInfo>();
        nuint resumeHandle = 0;

        do
        {
            var status = NetApiNative.NetLocalGroupGetMembers(
                serverName: null,
                localGroupName,
                level: 2,
                buffer: out var buffer,
                preferredMaximumLength: NetApiNative.MaxPreferredLength,
                entriesRead: out var entriesRead,
                totalEntries: out _,
                resumeHandle: ref resumeHandle);

            using var bufferHandle = new NetApiBufferSafeHandle(buffer);
            ThrowUnlessSuccessOrMoreData(status, nameof(NetApiNative.NetLocalGroupGetMembers));

            for (var index = 0u; index < entriesRead; index++)
            {
                var entry = Marshal.PtrToStructure<LocalGroupMembersInfo2Native>(OffsetOf<LocalGroupMembersInfo2Native>(buffer, index));
                members.Add(new LocalGroupMemberInfo(
                    Marshal.PtrToStringUni(entry.DomainAndName),
                    entry.SidUsage.ToString()));
            }

            if (status == NetApiNative.NerrSuccess)
            {
                return members;
            }
        }
        while (true);
    }

    private static IntPtr OffsetOf<T>(IntPtr buffer, uint index)
        where T : struct
    {
        var offset = checked((int)(Marshal.SizeOf<T>() * (long)index));
        return IntPtr.Add(buffer, offset);
    }

    private static void ThrowUnlessSuccessOrMoreData(int status, string operation)
    {
        if (status is not (NetApiNative.NerrSuccess or NetApiNative.ErrorMoreData))
        {
            throw new NetApiException(operation, status);
        }
    }
}
