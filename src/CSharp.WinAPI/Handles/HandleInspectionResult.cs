#pragma warning disable CS1591
namespace CSharp.WinAPI.Handles;
/// <summary>Immutable snapshot of metadata returned by the system handle table.</summary>
public sealed record HandleInspectionResult(IReadOnlyList<HandleInfo> Handles);
#pragma warning restore CS1591
