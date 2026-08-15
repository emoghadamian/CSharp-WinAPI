namespace CSharp.WinAPI.Processes;

/// <summary>Internal accumulator that preserves query order for legacy first-error compatibility.</summary>
internal sealed class ProcessInspectionDiagnosticsBuilder
{
    private const string OpenProcessUnavailable = "Not attempted because OpenProcess could not obtain a query-limited handle.";

    internal ProcessQueryDiagnostic ImagePath { get; private set; } = ProcessQueryDiagnostic.WasNotAttempted("Not attempted.");
    internal ProcessQueryDiagnostic CreationTime { get; private set; } = ProcessQueryDiagnostic.WasNotAttempted("Not attempted.");
    internal ProcessQueryDiagnostic SessionId { get; private set; } = ProcessQueryDiagnostic.WasNotAttempted("Not attempted.");
    internal ProcessQueryDiagnostic Architecture { get; private set; } = ProcessQueryDiagnostic.WasNotAttempted("Not attempted.");

    internal int? FirstNativeErrorCode { get; private set; }

    internal void SetImagePath(ProcessQueryDiagnostic diagnostic) => ImagePath = Record(diagnostic);
    internal void SetCreationTime(ProcessQueryDiagnostic diagnostic) => CreationTime = Record(diagnostic);
    internal void SetSessionId(ProcessQueryDiagnostic diagnostic) => SessionId = Record(diagnostic);
    internal void SetArchitecture(ProcessQueryDiagnostic diagnostic) => Architecture = Record(diagnostic);

    internal void MarkExtendedQueriesNotAttempted()
    {
        ImagePath = ProcessQueryDiagnostic.WasNotAttempted(OpenProcessUnavailable);
        CreationTime = ProcessQueryDiagnostic.WasNotAttempted(OpenProcessUnavailable);
        Architecture = ProcessQueryDiagnostic.WasNotAttempted(OpenProcessUnavailable);
    }

    internal ProcessInspectionDiagnostics? Build() =>
        ImagePath.Status == ProcessQueryStatus.Success &&
        CreationTime.Status == ProcessQueryStatus.Success &&
        SessionId.Status == ProcessQueryStatus.Success &&
        Architecture.Status == ProcessQueryStatus.Success
            ? null
            : new ProcessInspectionDiagnostics(ImagePath, CreationTime, SessionId, Architecture);

    private ProcessQueryDiagnostic Record(ProcessQueryDiagnostic diagnostic)
    {
        if (diagnostic.Status == ProcessQueryStatus.Failed)
        {
            FirstNativeErrorCode ??= diagnostic.NativeErrorCode;
        }

        return diagnostic;
    }
}
