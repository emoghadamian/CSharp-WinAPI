using System.ComponentModel;

namespace CSharp.WinAPI.Processes;

/// <summary>Immutable outcome metadata for one optional process-inspection query.</summary>
public sealed record ProcessQueryDiagnostic(ProcessQueryStatus Status, int? NativeErrorCode, string? Message)
{
    internal static ProcessQueryDiagnostic Succeeded { get; } = new(ProcessQueryStatus.Success, null, null);

    internal static ProcessQueryDiagnostic Failed(int errorCode) =>
        new(ProcessQueryStatus.Failed, errorCode, new Win32Exception(errorCode).Message);

    internal static ProcessQueryDiagnostic WasNotAttempted(string message) =>
        new(ProcessQueryStatus.NotAttempted, null, message);
}
