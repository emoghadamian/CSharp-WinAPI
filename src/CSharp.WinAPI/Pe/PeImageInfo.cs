namespace CSharp.WinAPI.Pe;

/// <summary>Read-only managed representation of a validated on-disk PE image.</summary>
public sealed class PeImageInfo
{
    private readonly IReadOnlyList<PeSectionInfo> sections;
    private readonly IReadOnlyList<PeDataDirectoryInfo> dataDirectories;
    private IReadOnlyList<PeImportModuleInfo> imports = Array.Empty<PeImportModuleInfo>();
    private PeExportInfo? exports;

    internal PeImageInfo(
        string filePath,
        uint peHeaderOffset,
        ushort machine,
        ushort numberOfSections,
        uint timeDateStamp,
        uint pointerToSymbolTable,
        uint numberOfSymbols,
        ushort sizeOfOptionalHeader,
        ushort characteristics,
        PeImageFormat format,
        byte majorLinkerVersion,
        byte minorLinkerVersion,
        uint sizeOfCode,
        uint sizeOfInitializedData,
        uint sizeOfUninitializedData,
        uint addressOfEntryPoint,
        uint baseOfCode,
        ulong imageBase,
        uint sectionAlignment,
        uint fileAlignment,
        uint sizeOfImage,
        uint sizeOfHeaders,
        ushort subsystem,
        ushort dllCharacteristics,
        ulong sizeOfStackReserve,
        ulong sizeOfStackCommit,
        ulong sizeOfHeapReserve,
        ulong sizeOfHeapCommit,
        uint numberOfRvaAndSizes,
        IReadOnlyList<PeSectionInfo> sections,
        IReadOnlyList<PeDataDirectoryInfo> dataDirectories)
    {
        FilePath = filePath;
        PeHeaderOffset = peHeaderOffset;
        Machine = machine;
        NumberOfSections = numberOfSections;
        TimeDateStamp = timeDateStamp;
        PointerToSymbolTable = pointerToSymbolTable;
        NumberOfSymbols = numberOfSymbols;
        SizeOfOptionalHeader = sizeOfOptionalHeader;
        Characteristics = characteristics;
        Format = format;
        MajorLinkerVersion = majorLinkerVersion;
        MinorLinkerVersion = minorLinkerVersion;
        SizeOfCode = sizeOfCode;
        SizeOfInitializedData = sizeOfInitializedData;
        SizeOfUninitializedData = sizeOfUninitializedData;
        AddressOfEntryPoint = addressOfEntryPoint;
        BaseOfCode = baseOfCode;
        ImageBase = imageBase;
        SectionAlignment = sectionAlignment;
        FileAlignment = fileAlignment;
        SizeOfImage = sizeOfImage;
        SizeOfHeaders = sizeOfHeaders;
        Subsystem = subsystem;
        DllCharacteristics = dllCharacteristics;
        SizeOfStackReserve = sizeOfStackReserve;
        SizeOfStackCommit = sizeOfStackCommit;
        SizeOfHeapReserve = sizeOfHeapReserve;
        SizeOfHeapCommit = sizeOfHeapCommit;
        NumberOfRvaAndSizes = numberOfRvaAndSizes;
        this.sections = sections;
        this.dataDirectories = dataDirectories;
    }

    /// <summary>Gets the inspected file path.</summary>
    public string FilePath { get; }
    /// <summary>Gets the file offset of the PE signature.</summary>
    public uint PeHeaderOffset { get; }
    /// <summary>Gets the unmodified IMAGE_FILE_HEADER machine value.</summary>
    public ushort Machine { get; }
    /// <summary>Gets the recognized machine architecture, or Unknown when the raw value is not classified.</summary>
    public PeMachineArchitecture Architecture => Machine switch { 0x014C => PeMachineArchitecture.I386, 0x8664 => PeMachineArchitecture.Amd64, 0xAA64 => PeMachineArchitecture.Arm64, _ => PeMachineArchitecture.Unknown };
    /// <summary>Gets the number of section headers.</summary>
    public ushort NumberOfSections { get; }
    /// <summary>Gets the raw COFF timestamp.</summary>
    public uint TimeDateStamp { get; }
    /// <summary>Gets the raw COFF symbol-table file offset.</summary>
    public uint PointerToSymbolTable { get; }
    /// <summary>Gets the raw COFF symbol count.</summary>
    public uint NumberOfSymbols { get; }
    /// <summary>Gets the optional-header byte size from IMAGE_FILE_HEADER.</summary>
    public ushort SizeOfOptionalHeader { get; }
    /// <summary>Gets the raw IMAGE_FILE_HEADER characteristics flags.</summary>
    public ushort Characteristics { get; }
    /// <summary>Gets the PE32 or PE32+ optional-header format.</summary>
    public PeImageFormat Format { get; }
    /// <summary>Gets the linker major version.</summary>
    public byte MajorLinkerVersion { get; }
    /// <summary>Gets the linker minor version.</summary>
    public byte MinorLinkerVersion { get; }
    /// <summary>Gets the total code size.</summary>
    public uint SizeOfCode { get; }
    /// <summary>Gets the total initialized-data size.</summary>
    public uint SizeOfInitializedData { get; }
    /// <summary>Gets the total uninitialized-data size.</summary>
    public uint SizeOfUninitializedData { get; }
    /// <summary>Gets the entry-point RVA.</summary>
    public uint AddressOfEntryPoint { get; }
    /// <summary>Gets the code base RVA.</summary>
    public uint BaseOfCode { get; }
    /// <summary>Gets the preferred image base.</summary>
    public ulong ImageBase { get; }
    /// <summary>Gets loaded-image section alignment.</summary>
    public uint SectionAlignment { get; }
    /// <summary>Gets on-disk section alignment.</summary>
    public uint FileAlignment { get; }
    /// <summary>Gets the loaded-image size.</summary>
    public uint SizeOfImage { get; }
    /// <summary>Gets the on-disk header size.</summary>
    public uint SizeOfHeaders { get; }
    /// <summary>Gets the raw subsystem value.</summary>
    public ushort Subsystem { get; }
    /// <summary>Gets the raw DLL characteristics flags.</summary>
    public ushort DllCharacteristics { get; }
    /// <summary>Gets stack reserve size.</summary>
    public ulong SizeOfStackReserve { get; }
    /// <summary>Gets stack commit size.</summary>
    public ulong SizeOfStackCommit { get; }
    /// <summary>Gets heap reserve size.</summary>
    public ulong SizeOfHeapReserve { get; }
    /// <summary>Gets heap commit size.</summary>
    public ulong SizeOfHeapCommit { get; }
    /// <summary>Gets the declared optional-header data-directory count.</summary>
    public uint NumberOfRvaAndSizes { get; }
    /// <summary>Gets parsed standard data-directory entries.</summary>
    public IReadOnlyList<PeDataDirectoryInfo> DataDirectories => dataDirectories;
    /// <summary>Gets parsed section headers.</summary>
    public IReadOnlyList<PeSectionInfo> Sections => sections;
    /// <summary>Gets normal import-directory modules and their imported functions.</summary>
    public IReadOnlyList<PeImportModuleInfo> Imports => imports;
    /// <summary>Gets whether the delay-import directory is present; delay-import contents are not parsed in this phase.</summary>
    public bool HasDelayImports => dataDirectories.Any(directory => directory.Kind == PeDataDirectoryKind.DelayImport && directory.IsPresent);
    /// <summary>Gets normal export-directory metadata, or null when the image has no export directory.</summary>
    public PeExportInfo? Exports => exports;

    internal void SetImports(IReadOnlyList<PeImportModuleInfo> parsedImports) => imports = parsedImports;
    internal void SetExports(PeExportInfo? parsedExports) => exports = parsedExports;

    /// <summary>Converts an RVA to its corresponding on-disk file offset.</summary>
    /// <exception cref="PeImageInspectionException">Thrown when the RVA has no raw-data representation in this image.</exception>
    public uint GetFileOffsetForRva(uint rva)
    {
        if (TryGetFileOffsetForRva(rva, out var fileOffset))
        {
            return fileOffset;
        }

        throw new PeImageInspectionException(FilePath, "RVA mapping", $"RVA 0x{rva:X8} does not map to available on-disk raw data.");
    }

    /// <summary>Attempts to convert an RVA to a validated on-disk file offset.</summary>
    public bool TryGetFileOffsetForRva(uint rva, out uint fileOffset)
    {
        if (rva < SizeOfHeaders)
        {
            fileOffset = rva;
            return true;
        }

        foreach (var section in sections)
        {
            if (rva < section.VirtualAddress)
            {
                continue;
            }

            var relativeOffset = (ulong)rva - section.VirtualAddress;
            var virtualExtent = Math.Max(section.VirtualSize, section.SizeOfRawData);

            if (relativeOffset >= virtualExtent || relativeOffset >= section.SizeOfRawData)
            {
                continue;
            }

            var mappedOffset = (ulong)section.PointerToRawData + relativeOffset;

            if (mappedOffset > uint.MaxValue)
            {
                break;
            }

            fileOffset = (uint)mappedOffset;
            return true;
        }

        fileOffset = 0;
        return false;
    }
}
