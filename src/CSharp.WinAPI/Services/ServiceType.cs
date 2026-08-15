namespace CSharp.WinAPI.Services;

/// <summary>Known SERVICE_TYPE flags retained from Windows service metadata.</summary>
[Flags]
public enum ServiceType : uint
{
    /// <summary>No known type flag.</summary>
    None = 0,
    /// <summary>Kernel driver.</summary>
    KernelDriver = 0x00000001,
    /// <summary>File-system driver.</summary>
    FileSystemDriver = 0x00000002,
    /// <summary>Adapter driver.</summary>
    Adapter = 0x00000004,
    /// <summary>Recognizer driver.</summary>
    RecognizerDriver = 0x00000008,
    /// <summary>Win32 service in its own process.</summary>
    Win32OwnProcess = 0x00000010,
    /// <summary>Win32 service sharing a process.</summary>
    Win32ShareProcess = 0x00000020,
    /// <summary>User service.</summary>
    UserService = 0x00000040,
    /// <summary>Package service.</summary>
    PackageService = 0x00000080,
    /// <summary>Interactive service-process flag.</summary>
    InteractiveProcess = 0x00000100,
    /// <summary>Mask of flags understood by this library.</summary>
    AllKnown = 0x0000013f,
}
