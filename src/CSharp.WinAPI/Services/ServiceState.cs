namespace CSharp.WinAPI.Services;

/// <summary>Known SERVICE_STATUS_PROCESS current-state values.</summary>
public enum ServiceState
{
    /// <summary>Unrecognized native value.</summary>
    Unknown,
    /// <summary>Service is stopped.</summary>
    Stopped,
    /// <summary>Service start is pending.</summary>
    StartPending,
    /// <summary>Service stop is pending.</summary>
    StopPending,
    /// <summary>Service is running.</summary>
    Running,
    /// <summary>Service continue is pending.</summary>
    ContinuePending,
    /// <summary>Service pause is pending.</summary>
    PausePending,
    /// <summary>Service is paused.</summary>
    Paused,
}
