namespace CSharp.WinAPI.Processes;

/// <summary>Immutable outcomes for the independent optional queries made while inspecting one process.</summary>
public sealed record ProcessInspectionDiagnostics(
    ProcessQueryDiagnostic ImagePath,
    ProcessQueryDiagnostic CreationTime,
    ProcessQueryDiagnostic SessionId,
    ProcessQueryDiagnostic Architecture);
