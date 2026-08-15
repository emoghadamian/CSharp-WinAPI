namespace CSharp.WinAPI.Etw;

/// <summary>Represents a registered local ETW provider metadata snapshot.</summary>
public sealed record EtwProviderInfo
{
    /// <summary>Initializes an ETW provider metadata snapshot.</summary>
    /// <param name="providerId">The provider GUID.</param>
    /// <param name="name">The provider name returned by TDH.</param>
    /// <param name="rawSchemaSource">The raw TDH schema-source value.</param>
    public EtwProviderInfo(Guid providerId, string name, uint rawSchemaSource)
    {
        ProviderId = providerId;
        Name = name;
        RawSchemaSource = rawSchemaSource;
    }

    /// <summary>Gets the unique provider GUID.</summary>
    public Guid ProviderId { get; }

    /// <summary>Gets the registered provider name.</summary>
    public string Name { get; }

    /// <summary>Gets the raw TDH schema-source value, including values newer than this library.</summary>
    public uint RawSchemaSource { get; }

    /// <summary>Gets the known schema-source interpretation, or <see langword="null"/> for an unknown value.</summary>
    public EtwProviderSchemaSource? SchemaSource => RawSchemaSource switch
    {
        (uint)EtwProviderSchemaSource.Manifest => EtwProviderSchemaSource.Manifest,
        (uint)EtwProviderSchemaSource.Mof => EtwProviderSchemaSource.Mof,
        _ => null
    };
}
