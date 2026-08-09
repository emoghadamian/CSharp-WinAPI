using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ThreadEnumeration;

/// <summary>Minimal raw Toolhelp32 example that intentionally exposes THREADENTRY32 initialization.</summary>
internal static partial class RawThreadSnapshot
{
    private const uint Th32CsSnapThread = 0x00000004;

    internal static RawThreadInfo ReadFirstThread()
    {
        var snapshot = CreateToolhelp32Snapshot(Th32CsSnapThread, processId: 0);

        if (snapshot == new IntPtr(-1))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        try
        {
            var entry = new ThreadEntry32Raw
            {
                Size = (uint)Marshal.SizeOf<ThreadEntry32Raw>(),
            };

            if (!Thread32First(snapshot, ref entry))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            return new RawThreadInfo(entry.ThreadId, entry.OwnerProcessId, entry.BasePriority);
        }
        finally
        {
            _ = CloseHandle(snapshot);
        }
    }

    // Native THREADENTRY32. dwSize must be initialized before Thread32First.
    [StructLayout(LayoutKind.Sequential)]
    private struct ThreadEntry32Raw
    {
        internal uint Size;
        internal uint UsageCount;
        internal uint ThreadId;
        internal uint OwnerProcessId;
        internal int BasePriority;
        internal int DeltaPriority;
        internal uint Flags;
    }

    // Native: HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID).
    [LibraryImport("kernel32.dll", EntryPoint = "CreateToolhelp32Snapshot", SetLastError = true)]
    private static partial IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    // Native: BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte).
    [LibraryImport("kernel32.dll", EntryPoint = "Thread32First", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Thread32First(IntPtr snapshot, ref ThreadEntry32Raw entry);

    // Native: BOOL CloseHandle(HANDLE hObject). Every real snapshot handle must be closed.
    [LibraryImport("kernel32.dll", EntryPoint = "CloseHandle")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);
}

internal sealed record RawThreadInfo(uint ThreadId, uint ProcessId, int BasePriority);
