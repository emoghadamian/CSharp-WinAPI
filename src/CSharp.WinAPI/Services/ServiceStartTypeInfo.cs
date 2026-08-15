namespace CSharp.WinAPI.Services;

/// <summary>A service start type with its authoritative native value.</summary>
public sealed record ServiceStartTypeInfo(uint RawValue, ServiceStartType Value);
