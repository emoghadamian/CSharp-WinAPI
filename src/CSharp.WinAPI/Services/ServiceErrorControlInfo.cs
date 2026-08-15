namespace CSharp.WinAPI.Services;

/// <summary>A service error-control value with its authoritative native value.</summary>
public sealed record ServiceErrorControlInfo(uint RawValue, ServiceErrorControl Value);
