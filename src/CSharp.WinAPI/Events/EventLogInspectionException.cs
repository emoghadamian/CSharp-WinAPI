namespace CSharp.WinAPI.Events;
/// <summary>Represents a native Windows Event Log failure or malformed Event Log data.</summary>
public sealed class EventLogInspectionException : Exception
{
    internal EventLogInspectionException(string operation, string? channelPath, int nativeErrorCode) : base($"{operation} failed{FormatChannel(channelPath)} with Win32 error {nativeErrorCode}: {new System.ComponentModel.Win32Exception(nativeErrorCode).Message}") { Operation = operation; ChannelPath = channelPath; NativeErrorCode = nativeErrorCode; }
    internal EventLogInspectionException(string operation, string? channelPath, string message, Exception? innerException = null) : base($"{operation} failed{FormatChannel(channelPath)}: {message}", innerException) { Operation = operation; ChannelPath = channelPath; }
    /// <summary>Gets the failed operation.</summary>
    public string Operation { get; }
    /// <summary>Gets the channel involved in the operation, when applicable.</summary>
    public string? ChannelPath { get; }
    /// <summary>Gets the native error code for a native failure; otherwise <see langword="null"/>.</summary>
    public int? NativeErrorCode { get; }
    private static string FormatChannel(string? path) => path is null ? string.Empty : $" for channel '{path}'";
}
