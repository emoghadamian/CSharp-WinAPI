# Windows service inspection

`ServiceInspector` provides read-only inventory and configuration metadata from the local Service Control Manager (SCM). It does not create, delete, start, stop, control, reconfigure, or secure services.

## SCM handles and ownership

`OpenSCManagerW` returns an SCM handle and `OpenServiceW` returns a service handle. Both are represented internally by `SafeServiceHandle` and are released only with `CloseServiceHandle`; they are not Win32 kernel handles and must not be passed to `CloseHandle`. No raw handle or native structure is public.

`EnumerateServices()` opens the SCM with `SC_MANAGER_ENUMERATE_SERVICE`. `InspectConfiguration(name)` opens the SCM with `SC_MANAGER_CONNECT` and the named service with `SERVICE_QUERY_CONFIG` only. Missing services, denied access, sizing failures, malformed returned data, and other failures become `ServiceInspectionException`, preserving the operation, service name when applicable, and the Win32 error code. A stopped service or a zero process ID is normal metadata, not an exception.

## Enumeration and status

`EnumServicesStatusExW` is called with process information, all documented service-type filters, and active plus inactive states. Its `ERROR_MORE_DATA` result is normal pagination: each returned page is parsed before its resume handle is reused. `servicesReturned` is the entry count; `bytesNeeded` is never treated as a count.

The implementation begins with a 64 KiB page, permits required page growth only up to 256 KiB, limits enumeration to 1,024 pages and 65,536 entries, and validates all native string pointers against the owned buffer. `ServiceInfo` retains service/display names, raw and interpreted state/type values, accepted controls, exit codes, checkpoint, wait hint, flags, and process ID. Unknown state/type bits remain available through raw values.

`ProcessId` is a correlation value only. Callers can pass a nonzero value to the existing `ProcessInspector` themselves; the service laboratory never opens or manipulates that process.

## Configuration

`QueryServiceConfigW` uses its documented two-call sizing pattern and rejects a requested configuration buffer over 8 KiB. `ServiceConfigurationInfo` preserves the exact binary-path string returned by Windows, including arguments; it does not normalize, expand, or execute it. Null pointers and empty strings remain distinct. Dependencies are parsed from the native double-null-terminated list, retaining a raw `+group` dependency and exposing its group meaning separately.

Start type, error control, and service type expose both a managed interpretation and the original numeric value. This is metadata, not a claim that a service is safe, trusted, active, or malicious.

## Scope, architecture, and learning layer

The layouts use fixed-width `DWORD` fields and pointer-sized `nint` only for native string pointers, so the AnyCPU library retains correct x86/x64/ARM64 ABI layout. Runtime behavior still requires validation on the target Windows architecture.

Service security-descriptor inspection is deferred. The repository already has dedicated file and registry descriptor laboratories; adding another parser and ownership lifecycle would expand this inventory/configuration phase without providing effective authorization or service-ACL modification. `QueryServiceObjectSecurity`, AccessCheck for services, and all security changes remain out of scope.

`examples/services/ServiceInspection` contrasts the managed API with a small raw `LibraryImport` example. Its raw handles and unmanaged buffers are explicitly closed/freed in `finally`; production code hides those lifetime details behind `SafeServiceHandle`.

## Microsoft references

- [OpenSCManagerW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) and [CloseServiceHandle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-closeservicehandle)
- [EnumServicesStatusExW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw) and [ENUM_SERVICE_STATUS_PROCESSW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-enum_service_status_processw)
- [QueryServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw) and [QUERY_SERVICE_CONFIGW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw)
