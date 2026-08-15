using System.ComponentModel;
using System.Runtime.InteropServices;
namespace NamedPipeInspection;
internal static partial class RawNamedPipeInspection
{
    private const int ErrorNoMoreFiles = 18;
    private const int MaximumShown = 8;

    internal static unsafe string Describe()
    {
        var search = FindFirstFile("\\\\.\\pipe\\*", out var data);
        if (search == (nint)(-1)) throw new Win32Exception(Marshal.GetLastPInvokeError());

        try
        {
            var names = new List<string> { ReadName(in data) };
            while (names.Count < MaximumShown && FindNextFile(search, out data)) names.Add(ReadName(in data));

            if (names.Count < MaximumShown)
            {
                var error = Marshal.GetLastPInvokeError();
                if (error != ErrorNoMoreFiles) throw new Win32Exception(error);
            }

            return string.Join(", ", names);
        }
        finally
        {
            _ = FindClose(search);
        }
    }

    private static unsafe string ReadName(in Data data)
    {
        fixed (char* value = data.Name)
        {
            var length = 0;
            while (length < 260 && value[length] != '\0') length++;
            if (length == 0 || length == 260) throw new Win32Exception(13, "Malformed pipe name.");
            return new string(value, 0, length);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private unsafe struct Data
    {
        internal fixed byte Prefix[44];
        internal fixed char Name[260];
    }

    [LibraryImport("kernel32.dll", EntryPoint = "FindFirstFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint FindFirstFile(string pattern, out Data data);

    [LibraryImport("kernel32.dll", EntryPoint = "FindNextFileW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FindNextFile(nint search, out Data data);

    [LibraryImport("kernel32.dll", EntryPoint = "FindClose", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FindClose(nint search);
}
