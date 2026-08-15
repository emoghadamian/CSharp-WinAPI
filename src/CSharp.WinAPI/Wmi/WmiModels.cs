#pragma warning disable CS1591
namespace CSharp.WinAPI.Wmi;
public sealed record WmiNamespacePath(string Namespace);
public sealed record WmiPropertyInfo(string Name, string CimType, bool IsArray);
public sealed record WmiClassInfo(string Name, string? ParentClass, IReadOnlyList<WmiPropertyInfo> Properties);
public sealed record WmiPropertyValue(string Name, string CimType, bool IsNull, string? Value);
public sealed record WmiInstanceInfo(string ClassName, IReadOnlyList<WmiPropertyValue> Properties);
#pragma warning restore CS1591
