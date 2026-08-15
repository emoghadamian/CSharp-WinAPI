using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Advapi32;

namespace CSharp.WinAPI.Services;

/// <summary>Provides read-only Windows service inventory and configuration inspection through SCM APIs.</summary>
public sealed class ServiceInspector
{
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorMoreData = 234;
    private const int ErrorInvalidParameter = 87;
    private const uint ScManagerConnect = 0x00000001;
    private const uint ScManagerEnumerateService = 0x00000004;
    private const uint ServiceQueryConfig = 0x00000001;
    private const uint ScEnumProcessInfo = 0;
    private const uint ServiceTypeAll = 0x0000013f;
    private const uint ServiceStateAll = 0x00000003;
    private const int InitialEnumerationBufferLength = 64 * 1024;
    private const int MaximumEnumerationBufferLength = 256 * 1024;
    private const int MaximumEnumerationPages = 1024;
    private const int MaximumEnumeratedServices = 65_536;
    private const int MaximumConfigurationBufferLength = 8 * 1024;

    /// <summary>Enumerates locally installed services and their current SCM status without opening individual service handles.</summary>
    public IReadOnlyList<ServiceInfo> EnumerateServices()
    {
        using var manager = OpenManager(ScManagerEnumerateService);
        var services = new List<ServiceInfo>();
        var resumeHandle = 0U;
        var bufferLength = InitialEnumerationBufferLength;

        for (var page = 0; page < MaximumEnumerationPages; page++)
        {
            var buffer = new byte[bufferLength];
            uint bytesNeeded;
            uint servicesReturned;
            bool succeeded;
            var resumeBefore = resumeHandle;

            unsafe
            {
                fixed (byte* bytes = buffer)
                {
                    succeeded = ServiceNative.EnumServicesStatusEx(
                        manager,
                        ScEnumProcessInfo,
                        ServiceTypeAll,
                        ServiceStateAll,
                        (nint)bytes,
                        (uint)buffer.Length,
                        out bytesNeeded,
                        out servicesReturned,
                        ref resumeHandle,
                        groupName: null);
                }
            }

            if (servicesReturned > MaximumEnumeratedServices || services.Count > MaximumEnumeratedServices - servicesReturned)
            {
                throw new ServiceInspectionException(nameof(ServiceNative.EnumServicesStatusEx), null, ErrorInvalidParameter);
            }

            if (servicesReturned > 0)
            {
                services.AddRange(ParseEnumerationPage(buffer, servicesReturned));
            }

            if (succeeded)
            {
                return Array.AsReadOnly(services.ToArray());
            }

            var errorCode = Marshal.GetLastPInvokeError();
            if (errorCode != ErrorMoreData)
            {
                throw new ServiceInspectionException(nameof(ServiceNative.EnumServicesStatusEx), null, errorCode);
            }

            if (servicesReturned == 0)
            {
                if (bytesNeeded == 0 || bytesNeeded > MaximumEnumerationBufferLength || bytesNeeded <= buffer.Length)
                {
                    throw new ServiceInspectionException(nameof(ServiceNative.EnumServicesStatusEx), null, ErrorInvalidParameter);
                }

                bufferLength = checked((int)bytesNeeded);
                continue;
            }

            if (resumeHandle == resumeBefore)
            {
                throw new ServiceInspectionException(nameof(ServiceNative.EnumServicesStatusEx), null, ErrorInvalidParameter);
            }
        }

        throw new ServiceInspectionException(nameof(ServiceNative.EnumServicesStatusEx), null, ErrorInvalidParameter);
    }

    /// <summary>Reads the stored configuration of one local service using SERVICE_QUERY_CONFIG only.</summary>
    public ServiceConfigurationInfo InspectConfiguration(string serviceName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);

        using var manager = OpenManager(ScManagerConnect);
        using var service = OpenService(manager, serviceName, ServiceQueryConfig);
        return QueryConfiguration(service, serviceName);
    }

    private static SafeServiceHandle OpenManager(uint access)
    {
        var manager = ServiceNative.OpenScManager(machineName: null, databaseName: null, access);
        if (!manager.IsInvalid)
        {
            return manager;
        }

        var errorCode = Marshal.GetLastPInvokeError();
        manager.Dispose();
        throw new ServiceInspectionException(nameof(ServiceNative.OpenScManager), null, errorCode);
    }

    private static SafeServiceHandle OpenService(SafeServiceHandle manager, string serviceName, uint access)
    {
        var service = ServiceNative.OpenService(manager, serviceName, access);
        if (!service.IsInvalid)
        {
            return service;
        }

        var errorCode = Marshal.GetLastPInvokeError();
        service.Dispose();
        throw new ServiceInspectionException(nameof(ServiceNative.OpenService), serviceName, errorCode);
    }

    private static ServiceConfigurationInfo QueryConfiguration(SafeServiceHandle service, string serviceName)
    {
        if (ServiceNative.QueryServiceConfig(service, nint.Zero, 0, out var bytesNeeded))
        {
            throw new ServiceInspectionException(nameof(ServiceNative.QueryServiceConfig), serviceName, ErrorInvalidParameter);
        }

        var errorCode = Marshal.GetLastPInvokeError();
        if (errorCode != ErrorInsufficientBuffer || bytesNeeded == 0 || bytesNeeded > MaximumConfigurationBufferLength)
        {
            throw new ServiceInspectionException(nameof(ServiceNative.QueryServiceConfig), serviceName, errorCode);
        }

        var buffer = new byte[checked((int)bytesNeeded)];
        unsafe
        {
            fixed (byte* bytes = buffer)
            {
                // pcbBytesNeeded is documented only for ERROR_INSUFFICIENT_BUFFER;
                // the successful call is bounded by the previously validated allocation.
                if (!ServiceNative.QueryServiceConfig(service, (nint)bytes, bytesNeeded, out _))
                {
                    throw LastError(nameof(ServiceNative.QueryServiceConfig), serviceName);
                }
            }
        }

        return ParseConfiguration(buffer, serviceName);
    }

    private static unsafe IReadOnlyList<ServiceInfo> ParseEnumerationPage(byte[] buffer, uint count)
    {
        var entrySize = Marshal.SizeOf<EnumServiceStatusProcessNative>();
        if ((ulong)count * (uint)entrySize > (uint)buffer.Length)
        {
            throw new ServiceInspectionException(nameof(ServiceNative.EnumServicesStatusEx), null, ErrorInvalidParameter);
        }

        var services = new List<ServiceInfo>((int)count);
        fixed (byte* bytes = buffer)
        {
            for (var index = 0U; index < count; index++)
            {
                var entry = Marshal.PtrToStructure<EnumServiceStatusProcessNative>((nint)(bytes + checked((int)(index * (uint)entrySize))));
                var serviceName = ReadUnicodeString(entry.ServiceName, (nint)bytes, buffer.Length, required: true, nameof(EnumServiceStatusProcessNative.ServiceName), null)!;
                var displayName = ReadUnicodeString(entry.DisplayName, (nint)bytes, buffer.Length, required: true, nameof(EnumServiceStatusProcessNative.DisplayName), serviceName)!;
                if (string.IsNullOrWhiteSpace(serviceName))
                {
                    throw new ServiceInspectionException(nameof(ServiceNative.EnumServicesStatusEx), serviceName, ErrorInvalidParameter);
                }

                var status = entry.Status;
                services.Add(new ServiceInfo(
                    serviceName,
                    displayName,
                    ToTypeInfo(status.ServiceType),
                    ToStateInfo(status.CurrentState),
                    status.ControlsAccepted,
                    status.Win32ExitCode,
                    status.ServiceSpecificExitCode,
                    status.CheckPoint,
                    status.WaitHint,
                    status.ProcessId,
                    status.ServiceFlags));
            }
        }

        return services;
    }

    private static unsafe ServiceConfigurationInfo ParseConfiguration(byte[] buffer, string serviceName)
    {
        var structureSize = Marshal.SizeOf<QueryServiceConfigNative>();
        if (buffer.Length < structureSize)
        {
            throw new ServiceInspectionException(nameof(ServiceNative.QueryServiceConfig), serviceName, ErrorInvalidParameter);
        }

        fixed (byte* bytes = buffer)
        {
            var configuration = Marshal.PtrToStructure<QueryServiceConfigNative>((nint)bytes);
            return new ServiceConfigurationInfo(
                serviceName,
                ReadUnicodeString(configuration.DisplayName, (nint)bytes, buffer.Length, required: false, nameof(QueryServiceConfigNative.DisplayName), serviceName),
                ToTypeInfo(configuration.ServiceType),
                ToStartTypeInfo(configuration.StartType),
                ToErrorControlInfo(configuration.ErrorControl),
                ReadUnicodeString(configuration.BinaryPathName, (nint)bytes, buffer.Length, required: false, nameof(QueryServiceConfigNative.BinaryPathName), serviceName),
                ReadUnicodeString(configuration.LoadOrderGroup, (nint)bytes, buffer.Length, required: false, nameof(QueryServiceConfigNative.LoadOrderGroup), serviceName),
                configuration.TagId == 0 ? null : configuration.TagId,
                ReadDependencies(configuration.Dependencies, (nint)bytes, buffer.Length, serviceName),
                ReadUnicodeString(configuration.ServiceStartName, (nint)bytes, buffer.Length, required: false, nameof(QueryServiceConfigNative.ServiceStartName), serviceName));
        }
    }

    private static unsafe IReadOnlyList<ServiceDependencyInfo> ReadDependencies(nint pointer, nint bufferStart, int bufferLength, string serviceName)
    {
        if (pointer == nint.Zero)
        {
            return Array.Empty<ServiceDependencyInfo>();
        }

        var dependencies = new List<ServiceDependencyInfo>();
        var current = pointer;
        while (true)
        {
            var value = ReadUnicodeString(current, bufferStart, bufferLength, required: true, nameof(QueryServiceConfigNative.Dependencies), serviceName)!;
            if (value.Length == 0)
            {
                return Array.AsReadOnly(dependencies.ToArray());
            }

            dependencies.Add(new ServiceDependencyInfo(value));
            current = checked(current + ((value.Length + 1) * sizeof(char)));
        }
    }

    private static unsafe string? ReadUnicodeString(nint pointer, nint bufferStart, int bufferLength, bool required, string field, string? serviceName)
    {
        if (pointer == nint.Zero)
        {
            if (!required)
            {
                return null;
            }

            throw new ServiceInspectionException(field, serviceName, ErrorInvalidParameter);
        }

        var start = (nuint)bufferStart;
        var end = checked(start + (uint)bufferLength);
        var address = (nuint)pointer;
        if (address < start || address >= end || ((address - start) & 1) != 0)
        {
            throw new ServiceInspectionException(field, serviceName, ErrorInvalidParameter);
        }

        var availableCharacters = (end - address) / sizeof(char);
        if (availableCharacters > int.MaxValue)
        {
            throw new ServiceInspectionException(field, serviceName, ErrorInvalidParameter);
        }

        var characters = (char*)pointer;
        for (var index = 0; index < (int)availableCharacters; index++)
        {
            if (characters[index] == '\0')
            {
                return new string(characters, 0, index);
            }
        }

        throw new ServiceInspectionException(field, serviceName, ErrorInvalidParameter);
    }

    private static ServiceTypeInfo ToTypeInfo(uint rawValue) => new(rawValue, (ServiceType)(rawValue & (uint)ServiceType.AllKnown));

    private static ServiceStateInfo ToStateInfo(uint rawValue) => new(rawValue, rawValue switch
    {
        1 => ServiceState.Stopped,
        2 => ServiceState.StartPending,
        3 => ServiceState.StopPending,
        4 => ServiceState.Running,
        5 => ServiceState.ContinuePending,
        6 => ServiceState.PausePending,
        7 => ServiceState.Paused,
        _ => ServiceState.Unknown,
    });

    private static ServiceStartTypeInfo ToStartTypeInfo(uint rawValue) => new(rawValue, rawValue switch
    {
        0 => ServiceStartType.Boot,
        1 => ServiceStartType.System,
        2 => ServiceStartType.Automatic,
        3 => ServiceStartType.Demand,
        4 => ServiceStartType.Disabled,
        _ => ServiceStartType.Unknown,
    });

    private static ServiceErrorControlInfo ToErrorControlInfo(uint rawValue) => new(rawValue, rawValue switch
    {
        0 => ServiceErrorControl.Ignore,
        1 => ServiceErrorControl.Normal,
        2 => ServiceErrorControl.Severe,
        3 => ServiceErrorControl.Critical,
        _ => ServiceErrorControl.Unknown,
    });

    private static ServiceInspectionException LastError(string operation, string serviceName) =>
        new(operation, serviceName, Marshal.GetLastPInvokeError());
}
