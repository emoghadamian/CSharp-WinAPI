using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace EtwProviderInspection;

// Provider metadata inspection does not start or enable ETW tracing.
internal static partial class RawEtwProviderInspection
{
    private const uint ErrorSuccess = 0;
    private const uint ErrorInsufficientBuffer = 122;
    private const int HeaderLength = 8;
    private const int ProviderInfoLength = 24;
    private const int MaximumBufferLength = 16 * 1024 * 1024;

    internal static string Describe()
    {
        uint size = 0;
        var status = TdhEnumerateProviders(0, ref size);
        if (status != ErrorInsufficientBuffer) throw new Win32Exception((int)status);

        for (var attempt = 0; attempt < 4; attempt++)
        {
            if (size < HeaderLength || size > MaximumBufferLength) throw new InvalidOperationException("TDH returned an invalid provider buffer length.");
            var buffer = GC.AllocateUninitializedArray<byte>(checked((int)size));
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                status = TdhEnumerateProviders(handle.AddrOfPinnedObject(), ref size);
                if (status == ErrorInsufficientBuffer) continue;
                if (status != ErrorSuccess) throw new Win32Exception((int)status);
                if (size > buffer.Length || size < HeaderLength) throw new InvalidOperationException("TDH returned an invalid used length.");

                return DescribeFirstProvider(buffer.AsSpan(0, checked((int)size)));
            }
            finally
            {
                handle.Free();
            }
        }

        throw new InvalidOperationException("Provider registration changed too frequently for the bounded raw example.");
    }

    private static string DescribeFirstProvider(ReadOnlySpan<byte> data)
    {
        var count = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (count == 0) return "No registered ETW providers.";
        if (count > 16_384 || data.Length < HeaderLength + ProviderInfoLength) throw new InvalidOperationException("Malformed TDH provider metadata.");

        var entry = data.Slice(HeaderLength, ProviderInfoLength);
        var providerId = new Guid(entry[..16]);
        var nameOffset = BinaryPrimitives.ReadUInt32LittleEndian(entry.Slice(20, 4));
        if ((nameOffset & 1) != 0 || nameOffset < HeaderLength + ProviderInfoLength || nameOffset > data.Length - 2)
            throw new InvalidOperationException("Malformed TDH provider-name offset.");

        var characters = new char[256];
        for (var index = 0; index < characters.Length; index++)
        {
            var offset = checked((int)nameOffset + index * sizeof(char));
            if (offset > data.Length - sizeof(char)) break;
            var character = (char)BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, sizeof(char)));
            if (character == '\0')
            {
                if (index == 0) break;
                return $"{providerId} {new string(characters, 0, index)}";
            }

            characters[index] = character;
        }

        throw new InvalidOperationException("Malformed or oversized TDH provider name.");
    }

    [LibraryImport("tdh.dll", EntryPoint = "TdhEnumerateProviders")]
    private static partial uint TdhEnumerateProviders(nint buffer, ref uint bufferSize);
}
