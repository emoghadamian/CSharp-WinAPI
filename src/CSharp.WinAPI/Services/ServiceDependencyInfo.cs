namespace CSharp.WinAPI.Services;

/// <summary>A dependency string returned by QUERY_SERVICE_CONFIGW.</summary>
public sealed record ServiceDependencyInfo(string RawName)
{
    /// <summary>Whether the dependency names a load-order group rather than a service.</summary>
    public bool IsLoadOrderGroup => RawName.StartsWith('+');

    /// <summary>Gets the dependency name without the native load-order-group prefix.</summary>
    public string Name => IsLoadOrderGroup ? RawName[1..] : RawName;
}
