namespace CSharp.WinAPI.Pipes;

/// <summary>Represents a locally visible named pipe.</summary>
public sealed record NamedPipeInfo
{
    /// <summary>Initializes a named-pipe metadata snapshot.</summary>
    /// <param name="name">The authoritative name returned by the local pipe namespace.</param>
    /// <param name="path">The corresponding local <c>\\.\pipe\</c> path.</param>
    public NamedPipeInfo(string name, string path)
    {
        Name = name;
        Path = path;
    }

    /// <summary>Gets the authoritative name returned by the local pipe namespace.</summary>
    public string Name { get; }

    /// <summary>Gets the corresponding local <c>\\.\pipe\</c> path.</summary>
    public string Path { get; }
}
