namespace CSharp.WinAPI.Events;
/// <summary>Specifies the order in which a channel query returns event records.</summary>
public enum EventLogQueryDirection
{
    /// <summary>Returns records from oldest to newest.</summary>
    Forward,

    /// <summary>Returns records from newest to oldest.</summary>
    Reverse,
}
