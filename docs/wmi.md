# WMI / CIM inspection

`WmiInspector` provides bounded, local-only read access to `ROOT\...` WMI namespaces through the supported `System.Management` layer. It uses strongly modeled class metadata and instance queries instead of exposing arbitrary WQL. The implementation never invokes WMI methods, creates subscriptions, uses remote endpoints or credentials, or changes namespaces, classes, instances, properties, tokens, or security.

WMI wrappers are COM-backed. The inspector enters an MTA apartment when it owns initialization and uninitializes only that owned initialization. Scopes, searchers, collections, objects, and classes are disposed immediately after immutable metadata conversion.

Namespaces are limited to 256 characters; class names to 256; classes to 4,096; properties to 256; instances to 1,024; string values to 64 KiB; and array elements to 256. Provider errors remain contextual `WmiInspectionException` failures, not empty results. WMI read access does not prove method-execution authorization, complete visibility, or maliciousness.

The managed example reads `Win32_OperatingSystem` and class metadata for `Win32_Service`. Values are data only. Runtime validation is on the current x64 host; x64/x86/ARM64 builds validate managed architecture compatibility.
