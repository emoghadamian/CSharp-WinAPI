using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ServiceInspection;

// Deliberately low-level contrast to ServiceInspector: raw handles and unmanaged buffers need explicit cleanup.
internal static partial class RawServiceInspection
{
    private const uint ScManagerEnumerateService = 0x00000004;
    private const uint ServiceQueryConfig = 0x00000001;
    private const uint ServiceTypeAll = 0x0000013f;
    private const uint ServiceStateAll = 0x00000003;
    private const int ErrorMoreData = 234;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorInvalidParameter = 87;
    private const int MaximumConfigurationBufferLength = 8 * 1024;

    internal static string DescribeFirstServiceConfiguration()
    {
        var manager = OpenScManager(null, null, ScManagerEnumerateService);
        if (manager == nint.Zero) throw new Win32Exception(Marshal.GetLastPInvokeError());

        try
        {
            const int pageLength = 64 * 1024;
            var page = Marshal.AllocHGlobal(pageLength);
            try
            {
                uint resumeHandle = 0;
                if (!EnumServicesStatusEx(manager, 0, ServiceTypeAll, ServiceStateAll, page, pageLength, out _, out var returned, ref resumeHandle, null) &&
                    (Marshal.GetLastPInvokeError() != ErrorMoreData || returned == 0))
                {
                    throw new Win32Exception(Marshal.GetLastPInvokeError());
                }

                if (returned == 0)
                {
                    throw new Win32Exception(ErrorInvalidParameter, "The SCM returned no service records.");
                }

                var first = Marshal.PtrToStructure<EnumServiceStatusProcessRaw>(page);
                var serviceName = ReadUnicodeString(first.ServiceName, page, pageLength, required: true, "The first service name was invalid.")!;
                var service = OpenService(manager, serviceName, ServiceQueryConfig);
                if (service == nint.Zero) throw new Win32Exception(Marshal.GetLastPInvokeError());

                try
                {
                    if (QueryServiceConfig(service, nint.Zero, 0, out var required) || Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer || required == 0)
                    {
                        throw new Win32Exception(Marshal.GetLastPInvokeError());
                    }

                    if (required > MaximumConfigurationBufferLength)
                    {
                        throw new Win32Exception(ErrorInvalidParameter, "QueryServiceConfigW reported a size above its documented maximum.");
                    }

                    var configurationBuffer = Marshal.AllocHGlobal(checked((int)required));
                    try
                    {
                        if (!QueryServiceConfig(service, configurationBuffer, required, out _))
                        {
                            throw new Win32Exception(Marshal.GetLastPInvokeError());
                        }

                        var configuration = Marshal.PtrToStructure<QueryServiceConfigRaw>(configurationBuffer);
                        var binaryPath = ReadUnicodeString(configuration.BinaryPathName, configurationBuffer, checked((int)required), required: false, "The binary-path pointer was invalid.");
                        return $"{serviceName}: start={configuration.StartType}, path={binaryPath ?? "<null>"}";
                    }
                    finally { Marshal.FreeHGlobal(configurationBuffer); }
                }
                finally { _ = CloseServiceHandle(service); }
            }
            finally { Marshal.FreeHGlobal(page); }
        }
        finally { _ = CloseServiceHandle(manager); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcessRaw
    {
        internal uint ServiceType;
        internal uint CurrentState;
        internal uint ControlsAccepted;
        internal uint Win32ExitCode;
        internal uint ServiceSpecificExitCode;
        internal uint CheckPoint;
        internal uint WaitHint;
        internal uint ProcessId;
        internal uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumServiceStatusProcessRaw
    {
        internal nint ServiceName;
        internal nint DisplayName;
        internal ServiceStatusProcessRaw Status;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigRaw
    {
        internal uint ServiceType;
        internal uint StartType;
        internal uint ErrorControl;
        internal nint BinaryPathName;
        internal nint LoadOrderGroup;
        internal uint TagId;
        internal nint Dependencies;
        internal nint ServiceStartName;
        internal nint DisplayName;
    }

    private static unsafe string? ReadUnicodeString(nint pointer, nint bufferStart, int bufferLength, bool required, string message)
    {
        if (pointer == nint.Zero)
        {
            if (!required) return null;
            throw new Win32Exception(ErrorInvalidParameter, message);
        }

        var start = (nuint)bufferStart;
        var end = checked(start + (uint)bufferLength);
        var address = (nuint)pointer;
        if (address < start || address >= end || ((address - start) & 1) != 0)
        {
            throw new Win32Exception(ErrorInvalidParameter, message);
        }

        var availableCharacters = (end - address) / sizeof(char);
        var characters = (char*)pointer;
        for (var index = 0; index < (int)availableCharacters; index++)
        {
            if (characters[index] == '\0') return new string(characters, 0, index);
        }

        throw new Win32Exception(ErrorInvalidParameter, message);
    }

    [LibraryImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenScManager(string? machineName, string? databaseName, uint desiredAccess);
    [LibraryImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenService(nint manager, string serviceName, uint desiredAccess);
    [LibraryImport("advapi32.dll", EntryPoint = "EnumServicesStatusExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EnumServicesStatusEx(nint manager, uint level, uint serviceType, uint serviceState, nint services, uint bufferSize, out uint bytesNeeded, out uint servicesReturned, ref uint resumeHandle, string? groupName);
    [LibraryImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryServiceConfig(nint service, nint configuration, uint bufferSize, out uint bytesNeeded);
    [LibraryImport("advapi32.dll", EntryPoint = "CloseServiceHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(nint handle);
}
