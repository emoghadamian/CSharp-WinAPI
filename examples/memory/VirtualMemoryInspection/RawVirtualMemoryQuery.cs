using System.ComponentModel;
using System.Runtime.InteropServices;

namespace VirtualMemoryInspection;

/// <summary>Minimal raw example that exposes MEMORY_BASIC_INFORMATION and deterministic process-handle cleanup.</summary>
internal static partial class RawVirtualMemoryQuery
{
    private const uint ProcessQueryInformation = 0x00000400;

    internal static RawMemoryRegion QueryFirstRegion(uint processId)
    {
        var process = OpenProcess(ProcessQueryInformation, false, processId);

        if (process == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        try
        {
            var bytesReturned = VirtualQueryEx(
                process,
                IntPtr.Zero,
                out var memoryInformation,
                (nuint)Marshal.SizeOf<MemoryBasicInformationRaw>());

            if (bytesReturned == 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            return new RawMemoryRegion(
                unchecked((nuint)memoryInformation.BaseAddress),
                unchecked((nuint)memoryInformation.AllocationBase),
                memoryInformation.RegionSize,
                memoryInformation.State,
                memoryInformation.Protect,
                memoryInformation.Type);
        }
        finally
        {
            _ = CloseHandle(process);
        }
    }

    // Native MEMORY_BASIC_INFORMATION. PVOID and SIZE_T are pointer-sized and PartitionId is followed by ABI padding.
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformationRaw
    {
        internal nint BaseAddress;
        internal nint AllocationBase;
        internal uint AllocationProtect;
        internal ushort PartitionId;
        internal nuint RegionSize;
        internal uint State;
        internal uint Protect;
        internal uint Type;
    }

    // Native: HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId).
    [LibraryImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
    private static partial IntPtr OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    // Native: SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength).
    [LibraryImport("kernel32.dll", EntryPoint = "VirtualQueryEx", SetLastError = true)]
    private static partial nuint VirtualQueryEx(
        IntPtr process,
        IntPtr address,
        out MemoryBasicInformationRaw memoryInformation,
        nuint memoryInformationLength);

    // Native: BOOL CloseHandle(HANDLE hObject). Every OpenProcess handle must be closed.
    [LibraryImport("kernel32.dll", EntryPoint = "CloseHandle")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);
}

internal sealed record RawMemoryRegion(
    nuint BaseAddress,
    nuint AllocationBase,
    nuint RegionSize,
    uint State,
    uint Protection,
    uint Type);
