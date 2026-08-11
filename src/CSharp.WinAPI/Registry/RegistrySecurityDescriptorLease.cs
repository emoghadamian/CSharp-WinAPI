using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Advapi32;

namespace CSharp.WinAPI.Registry;

/// <summary>Owns an opened registry key and pins its caller-owned security-descriptor buffer for a native call lifetime.</summary>
internal sealed class RegistrySecurityDescriptorLease : IDisposable
{
    private const int ErrorInsufficientBuffer = 122;
    private const int MaximumDescriptorLength = 16 * 1024 * 1024;
    private readonly SafeRegistryKeyHandle key;
    private readonly GCHandle pinnedBuffer;

    private RegistrySecurityDescriptorLease(RegistryKeyPath path, SafeRegistryKeyHandle key, byte[] buffer, GCHandle pinnedBuffer)
    {
        Path = path;
        this.key = key;
        Buffer = buffer;
        this.pinnedBuffer = pinnedBuffer;
    }

    internal RegistryKeyPath Path { get; }
    internal byte[] Buffer { get; }
    internal nint Pointer => pinnedBuffer.AddrOfPinnedObject();

    internal static RegistrySecurityDescriptorLease Open(RegistryKeyPath path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path.SubKey);
        var status = RegistryNative.RegOpenKeyEx(
            Root(path.Hive),
            path.SubKey,
            options: 0,
            RegistryAccessRights.ReadControl | ViewFlag(path.View),
            out var key);

        if (status != 0)
        {
            key.Dispose();
            throw new RegistrySecurityException(nameof(RegistryNative.RegOpenKeyEx), path, status);
        }

        try
        {
            uint length = 0;
            status = RegistryNative.RegGetKeySecurity(key, SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl, nint.Zero, ref length);
            if (status != ErrorInsufficientBuffer || length == 0 || length > MaximumDescriptorLength)
            {
                throw new RegistrySecurityException(nameof(RegistryNative.RegGetKeySecurity), path, status);
            }

            var buffer = new byte[checked((int)length)];
            var pinnedBuffer = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                var returnedLength = length;
                status = RegistryNative.RegGetKeySecurity(
                    key,
                    SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl,
                    pinnedBuffer.AddrOfPinnedObject(),
                    ref returnedLength);
                if (status != 0 || returnedLength == 0 || returnedLength > length)
                {
                    throw new RegistrySecurityException(nameof(RegistryNative.RegGetKeySecurity), path, status == 0 ? 87 : status);
                }

                return new RegistrySecurityDescriptorLease(path, key, buffer, pinnedBuffer);
            }
            catch
            {
                pinnedBuffer.Free();
                throw;
            }
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        pinnedBuffer.Free();
        key.Dispose();
    }

    private static nint Root(RegistryHive hive) => hive switch
    {
        RegistryHive.ClassesRoot => unchecked((nint)(int)0x80000000),
        RegistryHive.CurrentUser => unchecked((nint)(int)0x80000001),
        RegistryHive.LocalMachine => unchecked((nint)(int)0x80000002),
        RegistryHive.Users => unchecked((nint)(int)0x80000003),
        RegistryHive.CurrentConfig => unchecked((nint)(int)0x80000005),
        _ => throw new ArgumentOutOfRangeException(nameof(hive)),
    };

    private static RegistryAccessRights ViewFlag(RegistryView view) => view switch
    {
        RegistryView.Default => 0,
        RegistryView.Registry32 => RegistryAccessRights.Wow64_32Key,
        RegistryView.Registry64 => RegistryAccessRights.Wow64_64Key,
        _ => throw new ArgumentOutOfRangeException(nameof(view)),
    };
}
