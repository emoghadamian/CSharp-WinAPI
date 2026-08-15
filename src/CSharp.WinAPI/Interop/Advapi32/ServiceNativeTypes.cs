using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Advapi32;

[StructLayout(LayoutKind.Sequential)]
internal struct ServiceStatusProcessNative
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
internal struct EnumServiceStatusProcessNative
{
    internal nint ServiceName;
    internal nint DisplayName;
    internal ServiceStatusProcessNative Status;
}

[StructLayout(LayoutKind.Sequential)]
internal struct QueryServiceConfigNative
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
