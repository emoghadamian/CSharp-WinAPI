namespace CSharp.WinAPI.Services;

/// <summary>Known SERVICE_ACCEPT_* control flags.</summary>
[Flags]
public enum ServiceAcceptedControls : uint
{
    /// <summary>No accepted controls.</summary>
    None = 0,
    /// <summary>Stop control.</summary>
    Stop = 0x00000001,
    /// <summary>Pause and continue controls.</summary>
    PauseContinue = 0x00000002,
    /// <summary>Shutdown control.</summary>
    Shutdown = 0x00000004,
    /// <summary>Parameter-change control.</summary>
    ParameterChange = 0x00000008,
    /// <summary>Network-bind-change control.</summary>
    NetBindChange = 0x00000010,
    /// <summary>Hardware-profile-change control.</summary>
    HardwareProfileChange = 0x00000020,
    /// <summary>Power-event control.</summary>
    PowerEvent = 0x00000040,
    /// <summary>Session-change control.</summary>
    SessionChange = 0x00000080,
    /// <summary>Pre-shutdown control.</summary>
    PreShutdown = 0x00000100,
    /// <summary>Time-change control.</summary>
    TimeChange = 0x00000200,
    /// <summary>Trigger-event control.</summary>
    TriggerEvent = 0x00000400,
    /// <summary>User-mode reboot control.</summary>
    UserModeReboot = 0x00000800,
    /// <summary>Low-resource notification control.</summary>
    LowResources = 0x00002000,
    /// <summary>System-low-resource notification control.</summary>
    SystemLowResources = 0x00004000,
}
