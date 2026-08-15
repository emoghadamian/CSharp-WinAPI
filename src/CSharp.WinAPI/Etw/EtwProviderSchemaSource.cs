namespace CSharp.WinAPI.Etw;

/// <summary>Identifies the documented metadata source for an ETW provider when known.</summary>
public enum EtwProviderSchemaSource
{
    /// <summary>The provider supplies an XML instrumentation manifest.</summary>
    Manifest = 0,

    /// <summary>The provider supplies a WMI MOF class.</summary>
    Mof = 1
}
