using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Threads;

/// <summary>Provides read-only system and per-process thread enumeration through Toolhelp32 snapshots.</summary>
public sealed class ThreadInspector
{
    private const int ErrorInvalidData = 13;

    /// <summary>Enumerates all threads visible in a point-in-time Toolhelp32 snapshot.</summary>
    public IReadOnlyList<ThreadInfo> EnumerateThreads()
    {
        using var snapshot = Kernel32Native.CreateToolhelp32Snapshot(Kernel32Native.Th32CsSnapThread, processId: 0);

        if (snapshot.IsInvalid)
        {
            throw CreateLastErrorException(nameof(Kernel32Native.CreateToolhelp32Snapshot));
        }

        var threads = new List<ThreadInfo>();
        var entry = CreateThreadEntry();

        if (!Kernel32Native.Thread32First(snapshot, ref entry))
        {
            var errorCode = Marshal.GetLastPInvokeError();

            if (errorCode == Kernel32Native.ErrorNoMoreFiles)
            {
                return threads;
            }

            throw new ThreadInspectionException(nameof(Kernel32Native.Thread32First), errorCode);
        }

        while (true)
        {
            threads.Add(ToThreadInfo(entry));
            entry = CreateThreadEntry();

            if (Kernel32Native.Thread32Next(snapshot, ref entry))
            {
                continue;
            }

            var errorCode = Marshal.GetLastPInvokeError();

            if (errorCode == Kernel32Native.ErrorNoMoreFiles)
            {
                return threads;
            }

            throw new ThreadInspectionException(nameof(Kernel32Native.Thread32Next), errorCode);
        }
    }

    /// <summary>Enumerates threads whose Toolhelp owner-process ID matches <paramref name="processId"/>.</summary>
    public IReadOnlyList<ThreadInfo> EnumerateProcessThreads(uint processId) =>
        EnumerateThreads().Where(thread => thread.ProcessId == processId).ToArray();

    private static ThreadEntry32Native CreateThreadEntry() => new()
    {
        Size = (uint)Marshal.SizeOf<ThreadEntry32Native>(),
    };

    private static ThreadInfo ToThreadInfo(ThreadEntry32Native entry)
    {
        if (!entry.HasCoreInformation)
        {
            throw new ThreadInspectionException(nameof(ThreadEntry32Native), ErrorInvalidData);
        }

        return new ThreadInfo(entry.ThreadId, entry.OwnerProcessId, entry.BasePriority);
    }

    private static ThreadInspectionException CreateLastErrorException(string operation) =>
        new(operation, Marshal.GetLastPInvokeError());
}
