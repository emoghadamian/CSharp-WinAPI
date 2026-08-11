using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CSharp.WinAPI.Pe;

/// <summary>Validates and inspects read-only PE executable-image metadata from disk.</summary>
public sealed class PeImageInspector
{
    private const int MaximumImageLength = 64 * 1024 * 1024;
    private const int DosPeOffset = 0x3C;
    private const int CoffHeaderLength = 20;
    private const int SectionHeaderLength = 40;
    private const int MaximumSectionCount = 96;
    private const int ImportDescriptorLength = 20;
    private const int MaximumImportDescriptorCount = 4_096;
    private const int MaximumImportsPerModule = 16_384;
    private const int MaximumImportStringLength = 1_024;
    private const int ExportDirectoryLength = 40;
    private const int MaximumExportFunctionCount = 65_536;
    private const int MaximumCertificateEntryCount = 4_096;

    /// <summary>Inspects a PE file from disk without loading, executing, or modifying it.</summary>
    /// <exception cref="PeImageInspectionException">Thrown when the path cannot be read or the file is malformed.</exception>
    public PeImageInfo Inspect(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new PeImageInspectionException(filePath, "Path", "A non-empty file path is required.");
        }

        try
        {
            return Parse(filePath, ReadBoundedFile(filePath));
        }
        catch (PeImageInspectionException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new PeImageInspectionException(filePath, "File read", exception.Message, exception);
        }
    }

    private static byte[] ReadBoundedFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new PeImageInspectionException(filePath, "Path", "The file does not exist.");
        }

        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        if (stream.Length == 0 || stream.Length > MaximumImageLength)
        {
            throw new PeImageInspectionException(filePath, "File length", $"The file length must be between 1 and {MaximumImageLength:N0} bytes.");
        }

        var image = new byte[(int)stream.Length];
        var totalRead = 0;

        while (totalRead < image.Length)
        {
            var bytesRead = stream.Read(image, totalRead, image.Length - totalRead);

            if (bytesRead == 0)
            {
                throw new PeImageInspectionException(filePath, "File read", "The file was truncated while it was being read.");
            }

            totalRead += bytesRead;
        }

        return image;
    }

    private static PeImageInfo Parse(string filePath, byte[] image)
    {
        RequireRange(image, 0, DosPeOffset + sizeof(uint), filePath, "DOS header");

        if (ReadUInt16(image, 0, filePath, "DOS header") != 0x5A4D)
        {
            throw new PeImageInspectionException(filePath, "DOS header", "Missing MZ signature.");
        }

        var peOffset = ReadUInt32(image, DosPeOffset, filePath, "DOS header");
        RequireRange(image, peOffset, 4 + CoffHeaderLength, filePath, "PE header");

        if (ReadUInt32(image, peOffset, filePath, "PE header") != 0x00004550)
        {
            throw new PeImageInspectionException(filePath, "PE header", "Missing PE\\0\\0 signature.");
        }

        var coffOffset = checked(peOffset + 4U);
        var machine = ReadUInt16(image, coffOffset, filePath, "COFF header");
        var sectionCount = ReadUInt16(image, coffOffset + 2U, filePath, "COFF header");
        var timestamp = ReadUInt32(image, coffOffset + 4U, filePath, "COFF header");
        var symbolTable = ReadUInt32(image, coffOffset + 8U, filePath, "COFF header");
        var symbols = ReadUInt32(image, coffOffset + 12U, filePath, "COFF header");
        var optionalLength = ReadUInt16(image, coffOffset + 16U, filePath, "COFF header");
        var characteristics = ReadUInt16(image, coffOffset + 18U, filePath, "COFF header");

        if (sectionCount > MaximumSectionCount)
        {
            throw new PeImageInspectionException(filePath, "COFF header", $"Section count {sectionCount} exceeds the supported limit of {MaximumSectionCount}.");
        }

        var optionalOffset = checked(coffOffset + CoffHeaderLength);
        RequireRange(image, optionalOffset, optionalLength, filePath, "Optional header");
        var magic = ReadUInt16(image, optionalOffset, filePath, "Optional header");
        var format = magic switch
        {
            (ushort)PeImageFormat.Pe32 => PeImageFormat.Pe32,
            (ushort)PeImageFormat.Pe32Plus => PeImageFormat.Pe32Plus,
            _ => throw new PeImageInspectionException(filePath, "Optional header", $"Unsupported optional-header magic 0x{magic:X4}."),
        };
        var directoryOffset = format == PeImageFormat.Pe32 ? 96U : 112U;

        if (optionalLength < directoryOffset)
        {
            throw new PeImageInspectionException(filePath, "Optional header", "The optional header is truncated before its data-directory table.");
        }

        var imageBase = format == PeImageFormat.Pe32
            ? ReadUInt32(image, optionalOffset + 28U, filePath, "Optional header")
            : ReadUInt64(image, optionalOffset + 24U, filePath, "Optional header");
        var numberOfDirectories = ReadUInt32(image, optionalOffset + (format == PeImageFormat.Pe32 ? 92U : 108U), filePath, "Optional header");
        var availableDirectories = ((uint)optionalLength - directoryOffset) / 8U;

        if (numberOfDirectories > availableDirectories)
        {
            throw new PeImageInspectionException(filePath, "Data directories", "The declared data-directory count exceeds the optional-header bounds.");
        }

        var sectionOffset = checked(optionalOffset + optionalLength);
        var sectionTableLength = checked((uint)sectionCount * SectionHeaderLength);
        RequireRange(image, sectionOffset, sectionTableLength, filePath, "Section table");

        var sizeOfHeaders = ReadUInt32(image, optionalOffset + 60U, filePath, "Optional header");

        if (sizeOfHeaders > image.Length)
        {
            throw new PeImageInspectionException(filePath, "Optional header", "SizeOfHeaders extends beyond the file length.");
        }

        var directories = ParseDirectories(image, filePath, optionalOffset + directoryOffset, Math.Min(numberOfDirectories, 16U));
        var sections = ParseSections(image, filePath, sectionOffset, sectionCount, sizeOfHeaders);

        var parsedImage = new PeImageInfo(
            filePath,
            peOffset,
            machine,
            sectionCount,
            timestamp,
            symbolTable,
            symbols,
            optionalLength,
            characteristics,
            format,
            image[(int)(optionalOffset + 2U)],
            image[(int)(optionalOffset + 3U)],
            ReadUInt32(image, optionalOffset + 4U, filePath, "Optional header"),
            ReadUInt32(image, optionalOffset + 8U, filePath, "Optional header"),
            ReadUInt32(image, optionalOffset + 12U, filePath, "Optional header"),
            ReadUInt32(image, optionalOffset + 16U, filePath, "Optional header"),
            ReadUInt32(image, optionalOffset + 20U, filePath, "Optional header"),
            imageBase,
            ReadUInt32(image, optionalOffset + 32U, filePath, "Optional header"),
            ReadUInt32(image, optionalOffset + 36U, filePath, "Optional header"),
            ReadUInt32(image, optionalOffset + 56U, filePath, "Optional header"),
            sizeOfHeaders,
            ReadUInt16(image, optionalOffset + 68U, filePath, "Optional header"),
            ReadUInt16(image, optionalOffset + 70U, filePath, "Optional header"),
            ReadSizedValue(image, filePath, optionalOffset + 72U, format),
            ReadSizedValue(image, filePath, optionalOffset + (format == PeImageFormat.Pe32 ? 76U : 80U), format),
            ReadSizedValue(image, filePath, optionalOffset + (format == PeImageFormat.Pe32 ? 80U : 88U), format),
            ReadSizedValue(image, filePath, optionalOffset + (format == PeImageFormat.Pe32 ? 84U : 96U), format),
            numberOfDirectories,
            sections,
            directories);

        parsedImage.SetImports(ParseImports(parsedImage, image));
        parsedImage.SetExports(ParseExports(parsedImage, image));
        parsedImage.SetCertificateTable(ParseCertificateTable(parsedImage, image));
        return parsedImage;
    }

    private static PeCertificateTableInfo? ParseCertificateTable(PeImageInfo parsedImage, byte[] image)
    {
        var directory = parsedImage.DataDirectories.FirstOrDefault(entry => entry.Kind == PeDataDirectoryKind.CertificateTable);

        if (directory is null || (directory.Address == 0 && directory.Size == 0))
        {
            return null;
        }

        // PE uniquely defines Certificate Table VirtualAddress as a file offset, never an RVA.
        if (directory.Address == 0 || directory.Size < 8 || (ulong)directory.Address + directory.Size > (ulong)image.Length)
        {
            throw new PeImageInspectionException(parsedImage.FilePath, "Certificate table", "The certificate-table file offset or size is outside the file bounds.");
        }

        var tableEnd = (ulong)directory.Address + directory.Size;
        var cursor = (ulong)directory.Address;
        var entries = new List<PeCertificateInfo>();

        while (cursor < tableEnd)
        {
            if (entries.Count >= MaximumCertificateEntryCount)
            {
                throw new PeImageInspectionException(parsedImage.FilePath, "Certificate table", $"The certificate table exceeds the supported limit of {MaximumCertificateEntryCount:N0} entries.");
            }

            if (tableEnd - cursor < 8)
            {
                throw new PeImageInspectionException(parsedImage.FilePath, "Certificate table", "A WIN_CERTIFICATE header is truncated.");
            }

            var entryOffset = (uint)cursor;
            var length = ReadUInt32(image, entryOffset, parsedImage.FilePath, "Certificate table");

            if (length < 8 || cursor + length > tableEnd)
            {
                throw new PeImageInspectionException(parsedImage.FilePath, "Certificate table", "A WIN_CERTIFICATE length is invalid or extends outside the table.");
            }

            var revision = ReadUInt16(image, entryOffset + 4U, parsedImage.FilePath, "Certificate table");
            var type = ReadUInt16(image, entryOffset + 6U, parsedImage.FilePath, "Certificate table");
            var payloadOffset = entryOffset + 8U;
            var payloadLength = length - 8U;
            var metadata = type == (ushort)PeCertificateType.PkcsSignedData ? DecodeCms(image.AsSpan((int)payloadOffset, (int)payloadLength).ToArray(), parsedImage.FilePath) : (null, (int?)null, (string?)null);
            entries.Add(new PeCertificateInfo(length, revision, type, payloadOffset, payloadLength, metadata.Item1, metadata.Item2, metadata.Item3));
            var next = (cursor + length + 7UL) & ~7UL;

            if (next <= cursor || next > tableEnd)
            {
                throw new PeImageInspectionException(parsedImage.FilePath, "Certificate table", "WIN_CERTIFICATE alignment exceeds the certificate-table bounds.");
            }

            cursor = next;
        }

        return new PeCertificateTableInfo(directory.Address, directory.Size, entries);
    }

    private static (IReadOnlyList<PeX509CertificateInfo>?, int?, string?) DecodeCms(byte[] payload, string filePath)
    {
        try
        {
            var cms = new SignedCms();
            cms.Decode(payload);
            var certificates = cms.Certificates.Cast<X509Certificate2>().Select(certificate => new PeX509CertificateInfo(certificate.Subject, certificate.Issuer, certificate.SerialNumber, certificate.Thumbprint, certificate.NotBefore, certificate.NotAfter, certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? "Unknown", certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? "Unknown")).ToList();
            var digest = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0].DigestAlgorithm.FriendlyName ?? cms.SignerInfos[0].DigestAlgorithm.Value : null;
            return (certificates, cms.SignerInfos.Count, digest);
        }
        catch (CryptographicException exception)
        {
            throw new PeImageInspectionException(filePath, "PKCS#7", "The PKCS#7 signed-data payload is malformed.", exception);
        }
    }

    private static PeExportInfo? ParseExports(PeImageInfo parsedImage, byte[] image)
    {
        var exportDirectory = parsedImage.DataDirectories.FirstOrDefault(directory => directory.Kind == PeDataDirectoryKind.ExportTable);

        if (exportDirectory is null || (exportDirectory.Address == 0 && exportDirectory.Size == 0))
        {
            return null;
        }

        if (exportDirectory.Address == 0 || exportDirectory.Size < ExportDirectoryLength)
        {
            throw new PeImageInspectionException(parsedImage.FilePath, "Export directory", "The export directory has an invalid RVA or size.");
        }

        var directoryOffset = MapRva(parsedImage, exportDirectory.Address, "Export directory");
        var characteristics = ReadUInt32(image, directoryOffset, parsedImage.FilePath, "Export directory");
        var timestamp = ReadUInt32(image, checked(directoryOffset + 4U), parsedImage.FilePath, "Export directory");
        var majorVersion = ReadUInt16(image, checked(directoryOffset + 8U), parsedImage.FilePath, "Export directory");
        var minorVersion = ReadUInt16(image, checked(directoryOffset + 10U), parsedImage.FilePath, "Export directory");
        var nameRva = ReadUInt32(image, checked(directoryOffset + 12U), parsedImage.FilePath, "Export directory");
        var ordinalBase = ReadUInt32(image, checked(directoryOffset + 16U), parsedImage.FilePath, "Export directory");
        var numberOfFunctions = ReadUInt32(image, checked(directoryOffset + 20U), parsedImage.FilePath, "Export directory");
        var numberOfNames = ReadUInt32(image, checked(directoryOffset + 24U), parsedImage.FilePath, "Export directory");
        var addressOfFunctions = ReadUInt32(image, checked(directoryOffset + 28U), parsedImage.FilePath, "Export directory");
        var addressOfNames = ReadUInt32(image, checked(directoryOffset + 32U), parsedImage.FilePath, "Export directory");
        var addressOfNameOrdinals = ReadUInt32(image, checked(directoryOffset + 36U), parsedImage.FilePath, "Export directory");

        if (nameRva == 0 || numberOfFunctions > MaximumExportFunctionCount || numberOfNames > numberOfFunctions || addressOfFunctions == 0 || (numberOfNames > 0 && (addressOfNames == 0 || addressOfNameOrdinals == 0)))
        {
            throw new PeImageInspectionException(parsedImage.FilePath, "Export directory", "The export-directory counts or table RVAs are invalid.");
        }

        var imageName = ReadNullTerminatedAscii(parsedImage, image, nameRva, "Export DLL name");
        var namesByFunctionIndex = ParseExportNames(parsedImage, image, numberOfFunctions, numberOfNames, addressOfNames, addressOfNameOrdinals);
        var functions = ParseExportFunctions(parsedImage, image, exportDirectory, ordinalBase, numberOfFunctions, addressOfFunctions, namesByFunctionIndex);

        return new PeExportInfo(
            characteristics,
            timestamp,
            majorVersion,
            minorVersion,
            imageName,
            ordinalBase,
            numberOfFunctions,
            numberOfNames,
            addressOfFunctions,
            addressOfNames,
            addressOfNameOrdinals,
            functions);
    }

    private static string?[] ParseExportNames(PeImageInfo parsedImage, byte[] image, uint numberOfFunctions, uint numberOfNames, uint addressOfNames, uint addressOfNameOrdinals)
    {
        var namesByFunctionIndex = new string?[(int)numberOfFunctions];

        for (var nameIndex = 0U; nameIndex < numberOfNames; nameIndex++)
        {
            var namePointerRva = AddRva(addressOfNames, (ulong)nameIndex * sizeof(uint), parsedImage.FilePath, "Export name pointer table");
            var ordinalRva = AddRva(addressOfNameOrdinals, (ulong)nameIndex * sizeof(ushort), parsedImage.FilePath, "Export ordinal table");
            var nameRva = ReadUInt32(image, MapRva(parsedImage, namePointerRva, "Export name pointer table"), parsedImage.FilePath, "Export name pointer table");
            var functionIndex = ReadUInt16(image, MapRva(parsedImage, ordinalRva, "Export ordinal table"), parsedImage.FilePath, "Export ordinal table");

            if (functionIndex >= numberOfFunctions || nameRva == 0)
            {
                throw new PeImageInspectionException(parsedImage.FilePath, "Export ordinal table", "A named export references an invalid function index or name RVA.");
            }

            if (namesByFunctionIndex[(int)functionIndex] is not null)
            {
                throw new PeImageInspectionException(parsedImage.FilePath, "Export ordinal table", "Multiple export names reference the same function index.");
            }

            namesByFunctionIndex[(int)functionIndex] = ReadNullTerminatedAscii(parsedImage, image, nameRva, "Export name");
        }

        return namesByFunctionIndex;
    }

    private static IReadOnlyList<PeExportFunctionInfo> ParseExportFunctions(PeImageInfo parsedImage, byte[] image, PeDataDirectoryInfo exportDirectory, uint ordinalBase, uint numberOfFunctions, uint addressOfFunctions, string?[] namesByFunctionIndex)
    {
        var functions = new List<PeExportFunctionInfo>((int)numberOfFunctions);
        var forwarderRangeEnd = (ulong)exportDirectory.Address + exportDirectory.Size;

        for (var functionIndex = 0U; functionIndex < numberOfFunctions; functionIndex++)
        {
            var addressRva = AddRva(addressOfFunctions, (ulong)functionIndex * sizeof(uint), parsedImage.FilePath, "Export address table");
            var functionRva = ReadUInt32(image, MapRva(parsedImage, addressRva, "Export address table"), parsedImage.FilePath, "Export address table");
            var ordinal = (ulong)ordinalBase + functionIndex;

            if (ordinal > uint.MaxValue)
            {
                throw new PeImageInspectionException(parsedImage.FilePath, "Export address table", "The public export ordinal overflows 32 bits.");
            }

            var isForwarded = functionRva != 0 && functionRva >= exportDirectory.Address && functionRva < forwarderRangeEnd;
            var forwarderName = isForwarded ? ReadNullTerminatedAscii(parsedImage, image, functionRva, "Export forwarder") : null;
            functions.Add(new PeExportFunctionInfo(namesByFunctionIndex[(int)functionIndex], (uint)ordinal, isForwarded || functionRva == 0 ? null : functionRva, namesByFunctionIndex[(int)functionIndex] is not null, isForwarded, forwarderName));
        }

        return functions;
    }

    private static IReadOnlyList<PeImportModuleInfo> ParseImports(PeImageInfo parsedImage, byte[] image)
    {
        var importDirectory = parsedImage.DataDirectories.FirstOrDefault(directory => directory.Kind == PeDataDirectoryKind.ImportTable);

        if (importDirectory is null || (importDirectory.Address == 0 && importDirectory.Size == 0))
        {
            return Array.Empty<PeImportModuleInfo>();
        }

        if (importDirectory.Address == 0 || importDirectory.Size < ImportDescriptorLength)
        {
            throw new PeImageInspectionException(parsedImage.FilePath, "Import directory", "The import directory has an invalid RVA or size.");
        }

        var descriptorCapacity = importDirectory.Size / ImportDescriptorLength;

        if (descriptorCapacity > MaximumImportDescriptorCount)
        {
            throw new PeImageInspectionException(parsedImage.FilePath, "Import directory", "The import directory declares too many descriptors.");
        }

        var imports = new List<PeImportModuleInfo>((int)descriptorCapacity);

        for (var descriptorIndex = 0U; descriptorIndex < descriptorCapacity; descriptorIndex++)
        {
            var descriptorRva = AddRva(importDirectory.Address, (ulong)descriptorIndex * ImportDescriptorLength, parsedImage.FilePath, "Import directory");
            var descriptorOffset = MapRva(parsedImage, descriptorRva, "Import directory");
            var originalFirstThunk = ReadUInt32(image, descriptorOffset, parsedImage.FilePath, "Import directory");
            var timeDateStamp = ReadUInt32(image, checked(descriptorOffset + 4U), parsedImage.FilePath, "Import directory");
            var forwarderChain = ReadUInt32(image, checked(descriptorOffset + 8U), parsedImage.FilePath, "Import directory");
            var nameRva = ReadUInt32(image, checked(descriptorOffset + 12U), parsedImage.FilePath, "Import directory");
            var firstThunk = ReadUInt32(image, checked(descriptorOffset + 16U), parsedImage.FilePath, "Import directory");

            if (originalFirstThunk == 0 && timeDateStamp == 0 && forwarderChain == 0 && nameRva == 0 && firstThunk == 0)
            {
                return imports;
            }

            if (nameRva == 0 || firstThunk == 0)
            {
                throw new PeImageInspectionException(parsedImage.FilePath, "Import directory", "An import descriptor is missing its DLL name or IAT RVA.");
            }

            var lookupTableRva = originalFirstThunk == 0 ? firstThunk : originalFirstThunk;
            var name = ReadNullTerminatedAscii(parsedImage, image, nameRva, "Import DLL name");
            var functions = ParseImportFunctions(parsedImage, image, lookupTableRva, firstThunk);
            imports.Add(new PeImportModuleInfo(name, originalFirstThunk, firstThunk, timeDateStamp, forwarderChain, functions));
        }

        throw new PeImageInspectionException(parsedImage.FilePath, "Import directory", "The import descriptor table has no null terminator within its declared bounds.");
    }

    private static IReadOnlyList<PeImportFunctionInfo> ParseImportFunctions(PeImageInfo parsedImage, byte[] image, uint lookupTableRva, uint firstThunk)
    {
        var thunkWidth = parsedImage.Format == PeImageFormat.Pe32 ? 4U : 8U;
        var functions = new List<PeImportFunctionInfo>();

        for (var functionIndex = 0U; functionIndex < MaximumImportsPerModule; functionIndex++)
        {
            var relativeOffset = (ulong)functionIndex * thunkWidth;
            var lookupRva = AddRva(lookupTableRva, relativeOffset, parsedImage.FilePath, "Import lookup table");
            var lookupOffset = MapRva(parsedImage, lookupRva, "Import lookup table");
            var thunkValue = thunkWidth == 4
                ? ReadUInt32(image, lookupOffset, parsedImage.FilePath, "Import lookup table")
                : ReadUInt64(image, lookupOffset, parsedImage.FilePath, "Import lookup table");

            if (thunkValue == 0)
            {
                return functions;
            }

            var iatRva = AddRva(firstThunk, relativeOffset, parsedImage.FilePath, "Import address table");
            _ = MapRva(parsedImage, iatRva, "Import address table");

            if (IsOrdinalImport(thunkValue, parsedImage.Format))
            {
                ValidateOrdinalImport(thunkValue, parsedImage.Format, parsedImage.FilePath);
                functions.Add(new PeImportFunctionInfo(null, (ushort)thunkValue, true, null, lookupRva, iatRva));
                continue;
            }

            var hintNameRva = GetHintNameRva(thunkValue, parsedImage.Format, parsedImage.FilePath);
            var hintOffset = MapRva(parsedImage, hintNameRva, "Import hint/name");
            var hint = ReadUInt16(image, hintOffset, parsedImage.FilePath, "Import hint/name");
            var functionName = ReadNullTerminatedAscii(parsedImage, image, AddRva(hintNameRva, sizeof(ushort), parsedImage.FilePath, "Import hint/name"), "Import hint/name");
            functions.Add(new PeImportFunctionInfo(functionName, null, false, hint, lookupRva, iatRva));
        }

        throw new PeImageInspectionException(parsedImage.FilePath, "Import lookup table", "The thunk table has no null terminator within the configured safety limit.");
    }

    private static bool IsOrdinalImport(ulong thunkValue, PeImageFormat format) => format == PeImageFormat.Pe32
        ? (thunkValue & 0x80000000UL) != 0
        : (thunkValue & 0x8000000000000000UL) != 0;

    private static void ValidateOrdinalImport(ulong thunkValue, PeImageFormat format, string filePath)
    {
        var nonOrdinalBits = format == PeImageFormat.Pe32 ? thunkValue & 0x7FFF0000UL : thunkValue & 0x7FFFFFFFFFFF0000UL;

        if (nonOrdinalBits != 0)
        {
            throw new PeImageInspectionException(filePath, "Import lookup table", "An ordinal import has reserved bits set.");
        }
    }

    private static uint GetHintNameRva(ulong thunkValue, PeImageFormat format, string filePath)
    {
        var hintNameRva = format == PeImageFormat.Pe32 ? thunkValue & 0x7FFFFFFFUL : thunkValue & 0x7FFFFFFFFFFFFFFFUL;

        if (hintNameRva == 0 || hintNameRva > uint.MaxValue)
        {
            throw new PeImageInspectionException(filePath, "Import lookup table", "A name import has an invalid hint/name RVA.");
        }

        return (uint)hintNameRva;
    }

    private static string ReadNullTerminatedAscii(PeImageInfo parsedImage, byte[] image, uint startRva, string stage)
    {
        var bytes = new List<byte>();

        for (var index = 0U; index < MaximumImportStringLength; index++)
        {
            var rva = AddRva(startRva, index, parsedImage.FilePath, stage);
            var offset = MapRva(parsedImage, rva, stage);
            var value = image[(int)offset];

            if (value == 0)
            {
                return Encoding.ASCII.GetString(bytes.ToArray());
            }

            bytes.Add(value);
        }

        throw new PeImageInspectionException(parsedImage.FilePath, stage, $"The ASCII string exceeds {MaximumImportStringLength} bytes or has no null terminator.");
    }

    private static uint MapRva(PeImageInfo parsedImage, uint rva, string stage)
    {
        try
        {
            return parsedImage.GetFileOffsetForRva(rva);
        }
        catch (PeImageInspectionException exception)
        {
            throw new PeImageInspectionException(parsedImage.FilePath, stage, exception.Reason, exception);
        }
    }

    private static uint AddRva(uint baseRva, ulong relativeOffset, string filePath, string stage)
    {
        var result = (ulong)baseRva + relativeOffset;

        if (result > uint.MaxValue)
        {
            throw new PeImageInspectionException(filePath, stage, "An RVA calculation overflowed the 32-bit address space.");
        }

        return (uint)result;
    }

    private static IReadOnlyList<PeDataDirectoryInfo> ParseDirectories(byte[] image, string filePath, uint offset, uint count)
    {
        var directories = new List<PeDataDirectoryInfo>((int)count);

        for (var index = 0U; index < count; index++)
        {
            var entryOffset = checked(offset + (index * 8U));
            directories.Add(new PeDataDirectoryInfo(
                (PeDataDirectoryKind)index,
                ReadUInt32(image, entryOffset, filePath, "Data directories"),
                ReadUInt32(image, entryOffset + 4U, filePath, "Data directories"),
                index == 4));
        }

        return directories;
    }

    private static IReadOnlyList<PeSectionInfo> ParseSections(byte[] image, string filePath, uint offset, ushort count, uint sizeOfHeaders)
    {
        var sections = new List<PeSectionInfo>(count);

        for (var index = 0U; index < count; index++)
        {
            var sectionOffset = checked(offset + (index * SectionHeaderLength));
            var sizeOfRawData = ReadUInt32(image, sectionOffset + 16U, filePath, "Section table");
            var pointerToRawData = ReadUInt32(image, sectionOffset + 20U, filePath, "Section table");
            RequireRange(image, pointerToRawData, sizeOfRawData, filePath, "Section raw data");
            var virtualAddress = ReadUInt32(image, sectionOffset + 12U, filePath, "Section table");
            var virtualExtent = Math.Max(ReadUInt32(image, sectionOffset + 8U, filePath, "Section table"), sizeOfRawData);

            if ((ulong)virtualAddress + virtualExtent > (ulong)uint.MaxValue + 1UL)
            {
                throw new PeImageInspectionException(filePath, "Section table", "A section virtual range overflows the 32-bit RVA space.");
            }

            var section = new PeSectionInfo(
                ReadSectionName(image.AsSpan((int)sectionOffset, 8)),
                ReadUInt32(image, sectionOffset + 8U, filePath, "Section table"),
                virtualAddress,
                sizeOfRawData,
                pointerToRawData,
                ReadUInt32(image, sectionOffset + 24U, filePath, "Section table"),
                ReadUInt32(image, sectionOffset + 28U, filePath, "Section table"),
                ReadUInt16(image, sectionOffset + 32U, filePath, "Section table"),
                ReadUInt16(image, sectionOffset + 34U, filePath, "Section table"),
                (PeSectionCharacteristics)ReadUInt32(image, sectionOffset + 36U, filePath, "Section table"));
            ValidateUnambiguousRawRvaMapping(sections, section, sizeOfHeaders, filePath);
            sections.Add(section);
        }

        return sections;
    }

    private static void ValidateUnambiguousRawRvaMapping(IReadOnlyList<PeSectionInfo> sections, PeSectionInfo candidate, uint sizeOfHeaders, string filePath)
    {
        if (candidate.SizeOfRawData == 0)
        {
            return;
        }

        var candidateStart = (ulong)candidate.VirtualAddress;
        var candidateEnd = candidateStart + candidate.SizeOfRawData;

        if (candidateStart < sizeOfHeaders)
        {
            throw new PeImageInspectionException(filePath, "Section table", "A section raw RVA range overlaps the header RVA mapping.");
        }

        foreach (var section in sections)
        {
            if (section.SizeOfRawData == 0)
            {
                continue;
            }

            var sectionStart = (ulong)section.VirtualAddress;
            var sectionEnd = sectionStart + section.SizeOfRawData;

            if (candidateStart < sectionEnd && sectionStart < candidateEnd)
            {
                throw new PeImageInspectionException(filePath, "Section table", "Section raw RVA ranges overlap and would make RVA-to-file-offset mapping ambiguous.");
            }
        }
    }

    private static ulong ReadSizedValue(byte[] image, string filePath, uint offset, PeImageFormat format) => format == PeImageFormat.Pe32
        ? ReadUInt32(image, offset, filePath, "Optional header")
        : ReadUInt64(image, offset, filePath, "Optional header");

    private static string ReadSectionName(ReadOnlySpan<byte> name) => Encoding.ASCII.GetString(name).TrimEnd('\0');

    private static ushort ReadUInt16(byte[] image, uint offset, string filePath, string stage)
    {
        RequireRange(image, offset, sizeof(ushort), filePath, stage);
        return BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)offset));
    }

    private static uint ReadUInt32(byte[] image, uint offset, string filePath, string stage)
    {
        RequireRange(image, offset, sizeof(uint), filePath, stage);
        return BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)offset));
    }

    private static ulong ReadUInt64(byte[] image, uint offset, string filePath, string stage)
    {
        RequireRange(image, offset, sizeof(ulong), filePath, stage);
        return BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan((int)offset));
    }

    private static void RequireRange(byte[] image, uint offset, uint length, string filePath, string stage)
    {
        if ((ulong)offset + length > (ulong)image.Length)
        {
            throw new PeImageInspectionException(filePath, stage, "A required field extends beyond the file bounds.");
        }
    }
}
