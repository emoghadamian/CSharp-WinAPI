using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Wevtapi;

/// <summary>Raw declarations for the read-only Windows Event Log APIs used by this laboratory.</summary>
internal static partial class EventLogNative
{
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtOpenChannelEnum", SetLastError = true)] internal static partial nint EvtOpenChannelEnum(nint session, uint flags);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtNextChannelPath", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static partial bool EvtNextChannelPath(SafeEventHandle channelEnumerator, uint bufferSize, nint buffer, out uint bufferUsed);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtQuery", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] internal static partial nint EvtQuery(nint session, string path, string query, uint flags);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtNext", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static partial bool EvtNext(SafeEventHandle resultSet, uint eventsSize, nint events, uint timeout, uint flags, out uint returned);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtRender", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static partial bool EvtRender(nint context, SafeEventHandle fragment, uint flags, uint bufferSize, nint buffer, out uint bufferUsed, out uint propertyCount);
    [LibraryImport("wevtapi.dll", EntryPoint = "EvtClose", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static partial bool EvtClose(nint handle);
}
