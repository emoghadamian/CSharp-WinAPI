using CSharp.WinAPI.Interop.Tdh;

namespace CSharp.WinAPI.Etw;

/// <summary>Enumerates bounded, local, read-only ETW provider registration metadata.</summary>
public sealed class EtwProviderInspector
{
    private const uint ErrorSuccess = 0;
    private const uint ErrorInsufficientBuffer = 122;
    private const int MaximumBufferAttempts = 8;

    /// <summary>Returns an immutable snapshot of registered local ETW providers.</summary>
    public IReadOnlyList<EtwProviderInfo> EnumerateProviders()
    {
        uint bufferSize = 0;
        var status = EtwProviderNative.TdhEnumerateProviders(0, ref bufferSize);
        if (status == ErrorSuccess && bufferSize == 0) return Array.Empty<EtwProviderInfo>();
        if (status != ErrorInsufficientBuffer)
            throw new EtwProviderInspectionException(nameof(EtwProviderNative.TdhEnumerateProviders), status);

        for (var attempt = 0; attempt < MaximumBufferAttempts; attempt++)
        {
            var bufferLength = EtwProviderMetadataParser.ValidateBufferLength(bufferSize);
            var buffer = GC.AllocateUninitializedArray<byte>(bufferLength);
            using var lease = new PinnedBufferLease(buffer);
            status = EtwProviderNative.TdhEnumerateProviders(lease.Pointer, ref bufferSize);
            if (status == ErrorSuccess) return EtwProviderMetadataParser.Parse(buffer, bufferSize);
            if (status != ErrorInsufficientBuffer)
                throw new EtwProviderInspectionException(nameof(EtwProviderNative.TdhEnumerateProviders), status);
        }

        throw new EtwProviderInspectionException(nameof(EtwProviderNative.TdhEnumerateProviders), "Provider registration changed too frequently to obtain a bounded metadata snapshot.");
    }

    /// <summary>Returns providers whose names begin with <paramref name="prefix"/>, using already-enumerated metadata only.</summary>
    public IReadOnlyList<EtwProviderInfo> FindProvidersByNamePrefix(string prefix)
    {
        if (string.IsNullOrWhiteSpace(prefix) || prefix.Length > EtwProviderMetadataParser.MaximumProviderNameLength || prefix.Contains('\0'))
            throw new ArgumentException("The provider-name prefix must be nonempty, null-free, and no more than 256 characters.", nameof(prefix));

        return FilterByNamePrefix(EnumerateProviders(), prefix);
    }

    internal static IReadOnlyList<EtwProviderInfo> FilterByNamePrefix(IReadOnlyList<EtwProviderInfo> providers, string prefix)
    {
        var matches = new List<EtwProviderInfo>();
        foreach (var provider in providers)
            if (provider.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) matches.Add(provider);

        return matches.Count == 0 ? Array.Empty<EtwProviderInfo>() : Array.AsReadOnly(matches.ToArray());
    }
}
