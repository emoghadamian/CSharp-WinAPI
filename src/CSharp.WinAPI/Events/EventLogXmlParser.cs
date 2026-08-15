using System.Globalization;
using System.Xml;
using System.Xml.Linq;
namespace CSharp.WinAPI.Events;
/// <summary>Defensively converts rendered event XML into the stable managed record model.</summary>
internal static class EventLogXmlParser
{
    private const int MaximumFields = 512, MaximumNameLength = 256, MaximumValueLength = 16 * 1024;
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";
    internal static EventLogRecord Parse(string xml, string? expectedChannel = null)
    {
        ArgumentNullException.ThrowIfNull(xml);
        try
        {
            using var input = new StringReader(xml);
            using var reader = XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = EventLogInspector.MaximumRenderedXmlCharacters, MaxCharactersFromEntities = 0 });
            var root = XDocument.Load(reader, LoadOptions.PreserveWhitespace).Root;
            if (root is null || root.Name != Ns + "Event") throw new EventLogInspectionException("Parse event XML", expectedChannel, "The document root was not the Event namespace element.");
            var system = root.Element(Ns + "System");
            return new EventLogRecord((string?)system?.Element(Ns + "Provider")?.Attribute("Name"), UInt(system?.Element(Ns + "EventID")?.Value, "EventID", expectedChannel), Byte(system?.Element(Ns + "Version")?.Value, "Version", expectedChannel), Byte(system?.Element(Ns + "Level")?.Value, "Level", expectedChannel), UShort(system?.Element(Ns + "Task")?.Value, "Task", expectedChannel), Byte(system?.Element(Ns + "Opcode")?.Value, "Opcode", expectedChannel), system?.Element(Ns + "Keywords")?.Value, ULong(system?.Element(Ns + "EventRecordID")?.Value, "EventRecordID", expectedChannel), system?.Element(Ns + "Channel")?.Value, system?.Element(Ns + "Computer")?.Value, Time(system?.Element(Ns + "TimeCreated")?.Attribute("SystemTime")?.Value, expectedChannel), UInt(system?.Element(Ns + "Execution")?.Attribute("ProcessID")?.Value, "Execution/ProcessID", expectedChannel), UInt(system?.Element(Ns + "Execution")?.Attribute("ThreadID")?.Value, "Execution/ThreadID", expectedChannel), system?.Element(Ns + "Security")?.Attribute("UserID")?.Value, Fields(root, expectedChannel), xml);
        }
        catch (EventLogInspectionException) { throw; }
        catch (XmlException ex) { throw new EventLogInspectionException("Parse event XML", expectedChannel, "The rendered XML was malformed.", ex); }
    }
    private static IReadOnlyList<EventLogDataField> Fields(XElement root, string? channel) { var list = new List<EventLogDataField>(); foreach (var e in root.Element(Ns + "EventData")?.Elements(Ns + "Data") ?? Enumerable.Empty<XElement>()) { if (list.Count == MaximumFields) throw new EventLogInspectionException("Parse event XML", channel, "The event contained more EventData fields than the laboratory limit."); var n = (string?)e.Attribute("Name"); var v = e.Value; if (n is { Length: > MaximumNameLength } || v.Length > MaximumValueLength) throw new EventLogInspectionException("Parse event XML", channel, "An EventData field exceeded the laboratory limit."); list.Add(new(n, v)); } return list.Count == 0 ? Array.Empty<EventLogDataField>() : Array.AsReadOnly(list.ToArray()); }
    private static uint? UInt(string? v, string f, string? c) => Parse<uint>(v, uint.TryParse, f, c); private static ushort? UShort(string? v, string f, string? c) => Parse<ushort>(v, ushort.TryParse, f, c); private static byte? Byte(string? v, string f, string? c) => Parse<byte>(v, byte.TryParse, f, c); private static ulong? ULong(string? v, string f, string? c) => Parse<ulong>(v, ulong.TryParse, f, c);
    private static T? Parse<T>(string? v, Try<T> p, string f, string? c) where T : struct { if (string.IsNullOrEmpty(v)) return null; if (!p(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result)) throw new EventLogInspectionException("Parse event XML", c, $"The {f} value was malformed."); return result; }
    private static DateTimeOffset? Time(string? v, string? c) { if (string.IsNullOrEmpty(v)) return null; if (!DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var result)) throw new EventLogInspectionException("Parse event XML", c, "The TimeCreated/SystemTime value was malformed."); return result; }
    private delegate bool Try<T>(string value, NumberStyles style, IFormatProvider? provider, out T result);
}
