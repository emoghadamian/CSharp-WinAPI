namespace CSharp.WinAPI.Services;

/// <summary>Service-type flags with preservation of unknown future bits.</summary>
public sealed record ServiceTypeInfo(uint RawValue, ServiceType KnownFlags)
{
    /// <summary>Whether Windows returned bits not represented by <see cref="ServiceType"/>.</summary>
    public bool HasUnknownBits => (RawValue & ~(uint)ServiceType.AllKnown) != 0;
}
