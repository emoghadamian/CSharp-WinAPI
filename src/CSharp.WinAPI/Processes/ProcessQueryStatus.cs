namespace CSharp.WinAPI.Processes;

/// <summary>Describes whether one independent extended process query completed, failed, or was not reached.</summary>
public enum ProcessQueryStatus
{
    /// <summary>The native query completed successfully.</summary>
    Success,

    /// <summary>The native query was attempted but failed with a Win32 error.</summary>
    Failed,

    /// <summary>The native query was not attempted because an earlier prerequisite was unavailable.</summary>
    NotAttempted,
}
