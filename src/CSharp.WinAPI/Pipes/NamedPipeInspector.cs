using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Kernel32;
namespace CSharp.WinAPI.Pipes;
/// <summary>Enumerates bounded local named-pipe names without opening or connecting to any pipe.</summary>
public sealed class NamedPipeInspector
{
    private const int ErrorFileNotFound = 2;
    private const int ErrorNoMoreFiles = 18;
    private const int MaximumPipes = 16_384;

    /// <summary>Returns an immutable snapshot of locally visible pipe names and their <c>\\.\pipe\</c> paths.</summary>
    public IReadOnlyList<NamedPipeInfo> EnumerateLocalPipes()
    {
        var raw = NamedPipeNative.FindFirstFile("\\\\.\\pipe\\*", out var data);
        using var search = new SafeNamedPipeSearchHandle(raw);
        if (search.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorFileNotFound) return Array.Empty<NamedPipeInfo>();
            throw new NamedPipeInspectionException(nameof(NamedPipeNative.FindFirstFile), error);
        }

        var values = new List<NamedPipeInfo>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            if (values.Count == MaximumPipes)
                throw new NamedPipeInspectionException("Enumerate local named pipes", "The configured pipe count bound was exceeded.");

            var name = Name(in data);
            if (!names.Add(name))
                throw new NamedPipeInspectionException("Enumerate local named pipes", "The native enumeration returned a duplicate entry and did not make progress.");

            values.Add(new NamedPipeInfo(name, $"\\\\.\\pipe\\{name}"));
            if (NamedPipeNative.FindNextFile(search, out data)) continue;

            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorNoMoreFiles)
                return values.Count == 0 ? Array.Empty<NamedPipeInfo>() : Array.AsReadOnly(values.ToArray());

            throw new NamedPipeInspectionException(nameof(NamedPipeNative.FindNextFile), error);
        }
    }

    private static unsafe string Name(in Win32FindDataNative data)
    {
        fixed (char* chars = data.FileName)
            return NamedPipeEntryParser.Parse(new ReadOnlySpan<char>(chars, NamedPipeEntryParser.NativeBufferLength));
    }
}
