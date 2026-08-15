namespace CSharp.WinAPI.Pipes;

internal static class NamedPipeEntryParser
{
    internal const int MaximumNameLength = 259;
    internal const int NativeBufferLength = MaximumNameLength + 1;

    internal static string Parse(ReadOnlySpan<char> buffer)
    {
        if (buffer.Length != NativeBufferLength)
            throw new NamedPipeInspectionException("Parse named pipe entry", "The native pipe-name buffer had an unexpected length.");

        var terminator = buffer.IndexOf('\0');
        if (terminator == 0)
            throw new NamedPipeInspectionException("Parse named pipe entry", "The pipe name was empty.");
        if (terminator < 0)
            throw new NamedPipeInspectionException("Parse named pipe entry", "The pipe name was unterminated or exceeded the configured bound.");

        return buffer[..terminator].ToString();
    }
}
