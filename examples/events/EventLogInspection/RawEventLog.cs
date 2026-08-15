using System.ComponentModel;
using System.Runtime.InteropServices;
namespace EventLogInspection;
// Low-level contrast: every raw Event Log handle and buffer is explicitly released.
internal static partial class RawEventLog
{
    private const int InsufficientBuffer = 122, NoMoreItems = 259, MaximumXml = 1_048_576; private const uint QueryChannel = 1, QueryReverse = 0x200, RenderXml = 1;
    internal static unsafe string DescribeLatestSystemEvent()
    {
        var enumeration = EvtOpenChannelEnum(nint.Zero, 0); if (enumeration == nint.Zero) throw Error();
        try { if (EvtNextChannelPath(enumeration, 0, nint.Zero, out _) || Marshal.GetLastPInvokeError() != InsufficientBuffer) throw Error(); var query = EvtQuery(nint.Zero, "System", "*", QueryChannel | QueryReverse); if (query == nint.Zero) throw Error(); try { nint item = nint.Zero; if (!EvtNext(query, 1, (nint)(&item), 0, 0, out var returned)) { var error = Marshal.GetLastPInvokeError(); if (error == NoMoreItems && returned == 0) return "System has no records."; throw new Win32Exception(error); } if (item == nint.Zero || returned != 1) throw new Win32Exception(13, "Malformed EvtNext output."); try { if (EvtRender(nint.Zero, item, RenderXml, 0, nint.Zero, out var needed, out _) || Marshal.GetLastPInvokeError() != InsufficientBuffer || needed is < 2 or > MaximumXml || (needed & 1) != 0) throw Error(); var buffer = Marshal.AllocHGlobal((int)needed); try { if (!EvtRender(nint.Zero, item, RenderXml, needed, buffer, out var used, out _)) throw Error(); if (used is < 2 or > MaximumXml || used > needed || (used & 1) != 0) throw new Win32Exception(13, "Malformed EvtRender output."); return $"latest System XML has {used / 2 - 1} characters."; } finally { Marshal.FreeHGlobal(buffer); } } finally { _ = EvtClose(item); } } finally { _ = EvtClose(query); } } finally { _ = EvtClose(enumeration); }
    }
    private static Win32Exception Error() => new(Marshal.GetLastPInvokeError());
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtOpenChannelEnum", SetLastError = true)] private static partial nint EvtOpenChannelEnum(nint session, uint flags);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtNextChannelPath", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool EvtNextChannelPath(nint enumeration, uint bufferSize, nint buffer, out uint used);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtQuery", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] private static partial nint EvtQuery(nint session, string path, string query, uint flags);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtNext", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool EvtNext(nint resultSet, uint count, nint events, uint timeout, uint flags, out uint returned);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtRender", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool EvtRender(nint context, nint fragment, uint flags, uint bufferSize, nint buffer, out uint used, out uint properties);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtClose", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool EvtClose(nint handle);
}
