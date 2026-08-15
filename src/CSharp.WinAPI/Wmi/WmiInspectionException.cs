#pragma warning disable CS1591
namespace CSharp.WinAPI.Wmi;
public sealed class WmiInspectionException : Exception
{
    internal WmiInspectionException(string operation, string nameSpace, string? className, Exception inner) : base($"{operation} failed for {nameSpace}{(className is null ? string.Empty : $"/{className}")}: {inner.Message}", inner) { Operation = operation; Namespace = nameSpace; ClassName = className; HResultCode = inner.HResult; }
    internal WmiInspectionException(string operation, string nameSpace, string? className, string message) : base($"{operation} failed for {nameSpace}{(className is null ? string.Empty : $"/{className}")}: {message}") { Operation = operation; Namespace = nameSpace; ClassName = className; }
    public string Operation { get; }
    public string Namespace { get; }
    public string? ClassName { get; }
    public int? HResultCode { get; }
}
#pragma warning restore CS1591
