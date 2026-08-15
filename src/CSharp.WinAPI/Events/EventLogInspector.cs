using System.Runtime.InteropServices;
using System.Text;
using CSharp.WinAPI.Interop.Wevtapi;
namespace CSharp.WinAPI.Events;
/// <summary>Provides bounded, read-only local Windows Event Log channel enumeration and event querying.</summary>
public sealed class EventLogInspector
{
    private const int InsufficientBuffer = 122, NoMoreItems = 259, MaximumChannels = 4_096, MaximumChannelChars = 32_768, MaximumXPathCharacters = 16_384, MaximumEvents = 4_096, MaximumXmlBytes = 1_048_576;
    private const uint QueryChannel = 1, QueryForward = 0x100, QueryReverse = 0x200, RenderXml = 1;
    internal const int MaximumRenderedXmlCharacters = MaximumXmlBytes / sizeof(char);
    /// <summary>Enumerates registered local Event Log channel names as an immutable snapshot.</summary>
    public IReadOnlyList<string> EnumerateChannels()
    {
        using var h = new SafeEventHandle(EventLogNative.EvtOpenChannelEnum(nint.Zero, 0));
        if (h.IsInvalid) { var e = Marshal.GetLastPInvokeError(); h.Dispose(); throw new EventLogInspectionException(nameof(EventLogNative.EvtOpenChannelEnum), null, e); }
        var result = new List<string>();
        while (true) { var name = NextChannel(h); if (name is null) return Array.AsReadOnly(result.ToArray()); if (result.Count == MaximumChannels) throw new EventLogInspectionException("Enumerate event log channels", null, "The registered channel count exceeded the laboratory limit."); result.Add(name); }
    }
    /// <summary>Queries one local Event Log channel with a bounded XPath expression and renders matching records to XML.</summary>
    public IReadOnlyList<EventLogRecord> Query(string channelPath, string xpath, int maxEvents, EventLogQueryDirection direction = EventLogQueryDirection.Reverse)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(channelPath); ArgumentException.ThrowIfNullOrWhiteSpace(xpath);
        if (channelPath.Length > MaximumChannelChars || channelPath.IndexOf('\0') >= 0) throw new ArgumentException($"The channel path must not exceed {MaximumChannelChars} characters or contain a null character.", nameof(channelPath));
        if (xpath.Length > MaximumXPathCharacters || xpath.IndexOf('\0') >= 0) throw new ArgumentException($"The XPath must not exceed {MaximumXPathCharacters} characters or contain a null character.", nameof(xpath));
        if (maxEvents is < 1 or > MaximumEvents) throw new ArgumentOutOfRangeException(nameof(maxEvents), $"The maximum must be from 1 through {MaximumEvents}.");
        if (direction is not EventLogQueryDirection.Forward and not EventLogQueryDirection.Reverse) throw new ArgumentOutOfRangeException(nameof(direction));
        using var query = new SafeEventHandle(EventLogNative.EvtQuery(nint.Zero, channelPath, xpath, QueryChannel | (direction == EventLogQueryDirection.Forward ? QueryForward : QueryReverse)));
        if (query.IsInvalid) { var e = Marshal.GetLastPInvokeError(); query.Dispose(); throw new EventLogInspectionException(nameof(EventLogNative.EvtQuery), channelPath, e); }
        var records = new List<EventLogRecord>(maxEvents);
        while (records.Count < maxEvents) { var item = NextEvent(query, channelPath); if (item is null) break; using (item) records.Add(EventLogXmlParser.Parse(Xml(item, channelPath), channelPath)); }
        return records.Count == 0 ? Array.Empty<EventLogRecord>() : Array.AsReadOnly(records.ToArray());
    }
    private static unsafe string? NextChannel(SafeEventHandle h)
    {
        if (EventLogNative.EvtNextChannelPath(h, 0, nint.Zero, out var required)) throw new EventLogInspectionException(nameof(EventLogNative.EvtNextChannelPath), null, "The channel sizing probe unexpectedly succeeded.");
        var e = Marshal.GetLastPInvokeError(); if (e == NoMoreItems) return null; if (e != InsufficientBuffer || required is 0 or > MaximumChannelChars) throw new EventLogInspectionException(nameof(EventLogNative.EvtNextChannelPath), null, e);
        var b = new char[required]; fixed (char* p = b) { if (!EventLogNative.EvtNextChannelPath(h, required, (nint)p, out var used)) throw Last(nameof(EventLogNative.EvtNextChannelPath), null); if (used is 0 or > MaximumChannelChars || used > b.Length || b[used - 1] != '\0') throw new EventLogInspectionException(nameof(EventLogNative.EvtNextChannelPath), null, "The channel path output was malformed."); return new string(p, 0, checked((int)used - 1)); }
    }
    private static unsafe SafeEventHandle? NextEvent(SafeEventHandle q, string channel)
    {
        nint raw = nint.Zero; if (EventLogNative.EvtNext(q, 1, (nint)(&raw), 0, 0, out var returned)) { if (returned != 1 || raw == nint.Zero) throw new EventLogInspectionException(nameof(EventLogNative.EvtNext), channel, "The event result output was malformed."); return new SafeEventHandle(raw); }
        var e = Marshal.GetLastPInvokeError(); if (e == NoMoreItems && returned == 0) return null; throw new EventLogInspectionException(nameof(EventLogNative.EvtNext), channel, e);
    }
    private static unsafe string Xml(SafeEventHandle h, string channel)
    {
        if (EventLogNative.EvtRender(nint.Zero, h, RenderXml, 0, nint.Zero, out var required, out _)) throw new EventLogInspectionException(nameof(EventLogNative.EvtRender), channel, "The XML sizing probe unexpectedly succeeded.");
        var e = Marshal.GetLastPInvokeError(); if (e != InsufficientBuffer || required is < sizeof(char) or > MaximumXmlBytes || (required & 1) != 0) throw new EventLogInspectionException(nameof(EventLogNative.EvtRender), channel, e);
        var b = new byte[required]; fixed (byte* p = b) { if (!EventLogNative.EvtRender(nint.Zero, h, RenderXml, required, (nint)p, out var used, out _)) throw Last(nameof(EventLogNative.EvtRender), channel); if (used is < sizeof(char) or > MaximumXmlBytes || used > b.Length || (used & 1) != 0 || b[used - 1] != 0 || b[used - 2] != 0) throw new EventLogInspectionException(nameof(EventLogNative.EvtRender), channel, "The rendered XML output was malformed."); return Encoding.Unicode.GetString(b, 0, checked((int)used - sizeof(char))); }
    }
    private static EventLogInspectionException Last(string op, string? channel) => new(op, channel, Marshal.GetLastPInvokeError());
}
