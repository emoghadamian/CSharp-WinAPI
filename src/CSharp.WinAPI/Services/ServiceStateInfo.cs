namespace CSharp.WinAPI.Services;

/// <summary>A service state with its authoritative native value.</summary>
public sealed record ServiceStateInfo(uint RawValue, ServiceState Value);
