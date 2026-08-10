using System.Runtime.InteropServices;
using CSharp.WinAPI.Interop.Kernel32;

namespace CSharp.WinAPI.Memory;

/// <summary>Provides read-only virtual-memory metadata inspection through OpenProcess and VirtualQueryEx.</summary>
public sealed class VirtualMemoryInspector
{
    /// <summary>Enumerates all virtual-memory regions visible to the caller in the specified process.</summary>
    /// <remarks>
    /// The process is opened with PROCESS_QUERY_INFORMATION, the documented minimum right for VirtualQueryEx.
    /// This method returns region metadata only; it does not read, write, allocate, free, map, or protect memory.
    /// </remarks>
    /// <exception cref="MemoryInspectionException">Thrown when the process cannot be opened or a native query fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown if native metadata would make forward traversal unsafe.</exception>
    public IReadOnlyList<MemoryRegionInfo> EnumerateProcessMemory(uint processId)
    {
        using var process = Kernel32Native.OpenProcess(ProcessAccessRights.QueryInformation, false, processId);

        if (process.IsInvalid)
        {
            var errorCode = Marshal.GetLastPInvokeError();
            process.Dispose();
            throw new MemoryInspectionException(nameof(Kernel32Native.OpenProcess), errorCode);
        }

        Kernel32Native.GetSystemInfo(out var systemInformation);
        var maximumAddress = unchecked((nuint)systemInformation.MaximumApplicationAddress);
        var informationSize = (nuint)Marshal.SizeOf<MemoryBasicInformationNative>();
        var regions = new List<MemoryRegionInfo>();
        nuint address = 0;

        while (address <= maximumAddress)
        {
            var bytesReturned = Kernel32Native.VirtualQueryEx(
                process,
                unchecked((nint)address),
                out var memoryInformation,
                informationSize);

            if (bytesReturned == 0)
            {
                throw new MemoryInspectionException(nameof(Kernel32Native.VirtualQueryEx), Marshal.GetLastPInvokeError());
            }

            if (bytesReturned < informationSize)
            {
                throw new InvalidOperationException("VirtualQueryEx returned an incomplete MEMORY_BASIC_INFORMATION structure.");
            }

            var region = ToRegionInfo(memoryInformation);
            ValidateRegionForTraversal(region, address);
            regions.Add(region);

            var nextAddress = region.BaseAddress + region.RegionSize;

            if (nextAddress > maximumAddress)
            {
                return regions;
            }

            address = nextAddress;
        }

        return regions;
    }

    private static MemoryRegionInfo ToRegionInfo(MemoryBasicInformationNative memoryInformation) => new(
        unchecked((nuint)memoryInformation.BaseAddress),
        unchecked((nuint)memoryInformation.AllocationBase),
        memoryInformation.RegionSize,
        (MemoryState)memoryInformation.State,
        (MemoryProtection)memoryInformation.Protect,
        (MemoryProtection)memoryInformation.AllocationProtect,
        (MemoryType)memoryInformation.Type);

    private static void ValidateRegionForTraversal(MemoryRegionInfo region, nuint queriedAddress)
    {
        if (region.RegionSize == 0)
        {
            throw new InvalidOperationException("VirtualQueryEx returned a region with zero size.");
        }

        if (region.BaseAddress > queriedAddress)
        {
            throw new InvalidOperationException("VirtualQueryEx returned a region that does not include the queried address.");
        }

        if (region.BaseAddress > nuint.MaxValue - region.RegionSize)
        {
            throw new InvalidOperationException("VirtualQueryEx returned a region whose end address overflows the pointer-sized address range.");
        }

        if (region.BaseAddress + region.RegionSize <= queriedAddress)
        {
            throw new InvalidOperationException("VirtualQueryEx did not advance virtual-memory enumeration.");
        }
    }
}
