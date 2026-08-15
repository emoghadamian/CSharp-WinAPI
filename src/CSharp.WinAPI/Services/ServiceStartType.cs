namespace CSharp.WinAPI.Services;

/// <summary>Known SERVICE_START_TYPE values.</summary>
public enum ServiceStartType
{
    /// <summary>Unrecognized native value.</summary>
    Unknown,
    /// <summary>Boot-start driver.</summary>
    Boot,
    /// <summary>System-start driver.</summary>
    System,
    /// <summary>Automatic start.</summary>
    Automatic,
    /// <summary>Demand start.</summary>
    Demand,
    /// <summary>Disabled service.</summary>
    Disabled,
}
