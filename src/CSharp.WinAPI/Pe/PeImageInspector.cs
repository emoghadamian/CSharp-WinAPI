using System.Buffers.Binary;
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
        var sections = ParseSections(image, filePath, sectionOffset, sectionCount);

        return new PeImageInfo(
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

    private static IReadOnlyList<PeSectionInfo> ParseSections(byte[] image, string filePath, uint offset, ushort count)
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

            sections.Add(new PeSectionInfo(
                ReadSectionName(image.AsSpan((int)sectionOffset, 8)),
                ReadUInt32(image, sectionOffset + 8U, filePath, "Section table"),
                virtualAddress,
                sizeOfRawData,
                pointerToRawData,
                ReadUInt32(image, sectionOffset + 24U, filePath, "Section table"),
                ReadUInt32(image, sectionOffset + 28U, filePath, "Section table"),
                ReadUInt16(image, sectionOffset + 32U, filePath, "Section table"),
                ReadUInt16(image, sectionOffset + 34U, filePath, "Section table"),
                (PeSectionCharacteristics)ReadUInt32(image, sectionOffset + 36U, filePath, "Section table")));
        }

        return sections;
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
