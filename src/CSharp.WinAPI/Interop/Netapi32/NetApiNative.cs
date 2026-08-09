using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Netapi32;

/// <summary>Raw declarations for documented Netapi32 local-group APIs.</summary>
internal static partial class NetApiNative
{
    internal const int NerrSuccess = 0;
    internal const int ErrorMoreData = 234;
    internal const uint MaxPreferredLength = uint.MaxValue;

    [LibraryImport("Netapi32.dll", EntryPoint = "NetLocalGroupEnum", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int NetLocalGroupEnum(
        string? serverName,
        uint level,
        out IntPtr buffer,
        uint preferredMaximumLength,
        out uint entriesRead,
        out uint totalEntries,
        ref nuint resumeHandle);

    [LibraryImport("Netapi32.dll", EntryPoint = "NetLocalGroupGetMembers", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int NetLocalGroupGetMembers(
        string? serverName,
        string localGroupName,
        uint level,
        out IntPtr buffer,
        uint preferredMaximumLength,
        out uint entriesRead,
        out uint totalEntries,
        ref nuint resumeHandle);

    [LibraryImport("Netapi32.dll", EntryPoint = "NetApiBufferFree")]
    internal static partial int NetApiBufferFree(IntPtr buffer);
}
