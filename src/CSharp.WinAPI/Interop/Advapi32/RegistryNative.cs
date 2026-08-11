using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Advapi32;

[Flags]
internal enum RegistryAccessRights : uint { ReadControl = 0x00020000, Wow64_64Key = 0x0100, Wow64_32Key = 0x0200 }

internal static partial class RegistryNative
{
    [LibraryImport("advapi32.dll", EntryPoint = "RegOpenKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int RegOpenKeyEx(nint root, string subKey, uint options, RegistryAccessRights desiredAccess, out SafeRegistryKeyHandle result);
    [LibraryImport("advapi32.dll", EntryPoint = "RegGetKeySecurity")]
    internal static partial int RegGetKeySecurity(SafeRegistryKeyHandle key, SecurityInformation information, nint securityDescriptor, ref uint securityDescriptorLength);
    [LibraryImport("advapi32.dll", EntryPoint = "RegCloseKey")]
    internal static partial int RegCloseKey(nint key);
}

/// <summary>Owns only a non-predefined HKEY returned for an opened subkey.</summary>
internal sealed class SafeRegistryKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeRegistryKeyHandle() : base(true) { }
    protected override bool ReleaseHandle() => RegistryNative.RegCloseKey(handle) == 0;
}
