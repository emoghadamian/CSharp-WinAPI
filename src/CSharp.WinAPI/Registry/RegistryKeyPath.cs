namespace CSharp.WinAPI.Registry;

/// <summary>Local registry hive, subkey path, and view selection.</summary>
public sealed record RegistryKeyPath(RegistryHive Hive, string SubKey, RegistryView View = RegistryView.Default);
