using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Ntdll;
namespace CSharp.WinAPI.Handles;
/// <summary>Provides bounded, metadata-only system handle inventory without opening, duplicating, or closing foreign handles.</summary>
public sealed class HandleInspector
{
    private const int SystemExtendedHandleInformation = 64, StatusInfoLengthMismatch = unchecked((int)0xC0000004), InitialBuffer = 64 * 1024, MaximumBuffer = 64 * 1024 * 1024, MaximumHandles = 1_000_000;
    /// <summary>Returns an immutable snapshot of current system handle-table metadata.</summary>
    public HandleInspectionResult Inspect()
    {
        var length = InitialBuffer;
        while (true)
        {
            var buffer = new byte[length]; int status; uint needed;
            unsafe { fixed (byte* bytes = buffer) status = NtdllNative.NtQuerySystemInformation(SystemExtendedHandleInformation, (nint)bytes, (uint)buffer.Length, out needed); }
            if (status == 0) return new HandleInspectionResult(Parse(buffer, needed));
            if (status != StatusInfoLengthMismatch) throw new HandleInspectionException(nameof(NtdllNative.NtQuerySystemInformation), status, length);
            if (needed <= length || needed > MaximumBuffer) throw new HandleInspectionException(nameof(NtdllNative.NtQuerySystemInformation), "The requested handle-table buffer size was invalid or exceeded the configured maximum.");
            length = checked((int)needed);
        }
    }
    /// <summary>Filters an already collected snapshot without opening or querying any target handle.</summary>
    public static IReadOnlyList<HandleInfo> FilterByProcess(HandleInspectionResult result, uint processId)
    {
        ArgumentNullException.ThrowIfNull(result); var values = result.Handles.Where(handle => handle.ProcessId == processId).ToArray(); return values.Length == 0 ? Array.Empty<HandleInfo>() : Array.AsReadOnly(values);
    }
    private static unsafe IReadOnlyList<HandleInfo> Parse(byte[] buffer, uint returned)
    {
        var entrySize = IntPtr.Size == 8 ? 40 : 28; var used = returned == 0 ? buffer.Length : checked((int)returned);
        if (used > buffer.Length || used < IntPtr.Size * 2) throw new HandleInspectionException("Parse SystemExtendedHandleInformation", "The native result was truncated.");
        fixed (byte* bytes = buffer)
        {
            var count = IntPtr.Size == 8 ? *(ulong*)bytes : *(uint*)bytes;
            if (count > MaximumHandles || count > (ulong)((used - IntPtr.Size * 2) / entrySize)) throw new HandleInspectionException("Parse SystemExtendedHandleInformation", "The native handle count exceeded the validated buffer range.");
            var handles = new HandleInfo[(int)count]; var offset = IntPtr.Size * 2;
            for (var index = 0; index < (int)count; index++, offset += entrySize)
            {
                var entry = bytes + offset; var pid = IntPtr.Size == 8 ? *(ulong*)(entry + IntPtr.Size) : *(uint*)(entry + IntPtr.Size);
                if (pid > uint.MaxValue) throw new HandleInspectionException("Parse SystemExtendedHandleInformation", "A process identifier was not representable.");
                var handle = IntPtr.Size == 8 ? *(ulong*)(entry + IntPtr.Size * 2) : *(uint*)(entry + IntPtr.Size * 2); var tail = entry + IntPtr.Size * 3;
                handles[index] = new HandleInfo((uint)pid, (nuint)handle, *(ushort*)(tail + 6), *(uint*)tail, *(uint*)(tail + 8), *(ushort*)(tail + 4));
            }
            return handles.Length == 0 ? Array.Empty<HandleInfo>() : Array.AsReadOnly(handles);
        }
    }
}
