#pragma warning disable CS1591
namespace CSharp.WinAPI.Tasks;
public sealed class ScheduledTaskInspectionException : Exception
{
    internal ScheduledTaskInspectionException(string operation, string? path, Exception inner) : base($"{operation} failed{(path is null ? string.Empty : $" for '{path}'")}: {inner.Message}", inner) { Operation = operation; Path = path; HResultCode = inner.HResult; }
    internal ScheduledTaskInspectionException(string operation, string? path, string message) : base($"{operation} failed{(path is null ? string.Empty : $" for '{path}'")}: {message}") { Operation = operation; Path = path; }
    public string Operation { get; }
    public string? Path { get; }
    public int? HResultCode { get; }
}
#pragma warning restore CS1591
