namespace CSharp.WinAPI.Pe;

/// <summary>Creates compact, non-mutable snapshots for public PE model collections.</summary>
internal static class PeCollectionSnapshot
{
    internal static IReadOnlyList<T> Create<T>(IReadOnlyList<T> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        return Array.AsReadOnly(values.ToArray());
    }
}
