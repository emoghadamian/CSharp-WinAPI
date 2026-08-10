namespace CSharp.WinAPI.Pe;

/// <summary>Names the standard PE data-directory slots.</summary>
public enum PeDataDirectoryKind
{
    /// <summary>Export table.</summary>
    ExportTable,
    /// <summary>Import table.</summary>
    ImportTable,
    /// <summary>Resource table.</summary>
    ResourceTable,
    /// <summary>Exception table.</summary>
    ExceptionTable,
    /// <summary>Attribute certificate table.</summary>
    CertificateTable,
    /// <summary>Base relocation table.</summary>
    BaseRelocationTable,
    /// <summary>Debug directory.</summary>
    Debug,
    /// <summary>Architecture-specific directory.</summary>
    Architecture,
    /// <summary>Global pointer directory.</summary>
    GlobalPointer,
    /// <summary>TLS directory.</summary>
    Tls,
    /// <summary>Load-config directory.</summary>
    LoadConfig,
    /// <summary>Bound-import directory.</summary>
    BoundImport,
    /// <summary>Import address table.</summary>
    ImportAddressTable,
    /// <summary>Delay-import directory.</summary>
    DelayImport,
    /// <summary>CLR runtime header.</summary>
    ClrRuntimeHeader,
    /// <summary>Reserved directory.</summary>
    Reserved,
}
