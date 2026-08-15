using System.Buffers.Binary;

namespace CSharp.WinAPI.Etw;

internal static class EtwProviderMetadataParser
{
    internal const int MaximumProviderCount = 16_384;
    internal const int MaximumProviderNameLength = 256;
    internal const int MaximumMetadataBufferLength = 16 * 1024 * 1024;
    private const int HeaderLength = 8;
    private const int ProviderInfoLength = 24;

    internal static int ValidateBufferLength(uint length)
    {
        if (length < HeaderLength)
            throw new EtwProviderInspectionException("Validate TDH provider buffer", "TDH returned a buffer smaller than the PROVIDER_ENUMERATION_INFO header.");
        if (length > MaximumMetadataBufferLength)
            throw new EtwProviderInspectionException("Validate TDH provider buffer", $"TDH requested {length} bytes, exceeding the {MaximumMetadataBufferLength}-byte safety limit.");

        return checked((int)length);
    }

    internal static IReadOnlyList<EtwProviderInfo> Parse(ReadOnlySpan<byte> buffer, uint usedLength)
    {
        var length = ValidateBufferLength(usedLength);
        if (length > buffer.Length)
            throw new EtwProviderInspectionException("Parse TDH provider buffer", "TDH reported a used length larger than the caller-owned buffer.");

        var data = buffer[..length];
        var count = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (count > MaximumProviderCount)
            throw new EtwProviderInspectionException("Parse TDH provider buffer", $"TDH returned {count} providers, exceeding the {MaximumProviderCount}-provider safety limit.");

        var entriesLength = checked(HeaderLength + checked((int)count * ProviderInfoLength));
        if (entriesLength > data.Length)
            throw new EtwProviderInspectionException("Parse TDH provider buffer", "The provider entry array extends beyond the caller-owned buffer.");
        if (count == 0) return Array.Empty<EtwProviderInfo>();

        var providers = new EtwProviderInfo[count];
        for (var index = 0; index < providers.Length; index++)
        {
            var entryOffset = checked(HeaderLength + index * ProviderInfoLength);
            var entry = data.Slice(entryOffset, ProviderInfoLength);
            var providerId = new Guid(entry[..16]);
            var rawSchemaSource = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(16, 4));
            var nameOffset = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(20, 4));
            providers[index] = new EtwProviderInfo(providerId, ReadName(data, nameOffset, entriesLength), rawSchemaSource);
        }

        return Array.AsReadOnly(providers);
    }

    private static string ReadName(ReadOnlySpan<byte> data, uint offset, int entriesLength)
    {
        if ((offset & 1) != 0 || offset < entriesLength || offset > data.Length - 2)
            throw new EtwProviderInspectionException("Parse TDH provider name", "The provider-name offset was outside the string area of the caller-owned buffer.");

        var characters = new char[MaximumProviderNameLength];
        for (var index = 0; index < characters.Length; index++)
        {
            var byteOffset = checked((int)offset + index * sizeof(char));
            if (byteOffset > data.Length - sizeof(char))
                throw new EtwProviderInspectionException("Parse TDH provider name", "The provider name was unterminated within the caller-owned buffer.");

            var character = (char)BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(byteOffset, sizeof(char)));
            if (character == '\0')
            {
                if (index == 0) throw new EtwProviderInspectionException("Parse TDH provider name", "The provider name was empty.");
                return new string(characters, 0, index);
            }

            characters[index] = character;
        }

        throw new EtwProviderInspectionException("Parse TDH provider name", $"The provider name exceeded the {MaximumProviderNameLength}-character safety limit.");
    }
}
