using CSharp.WinAPI.Memory;
using VirtualMemoryInspection;

// Process -> OpenProcess(PROCESS_QUERY_INFORMATION) -> VirtualQueryEx -> MEMORY_BASIC_INFORMATION.
// This example observes metadata only; it never reads or alters remote or local memory.
var processId = (uint)Environment.ProcessId;
var inspector = new VirtualMemoryInspector();

try
{
    var regions = inspector.EnumerateProcessMemory(processId);
    var committedRegions = regions.Where(region => region.State == MemoryState.Commit).ToList();

    Console.WriteLine($"Virtual-memory regions for current process ({processId}): {regions.Count}");
    Console.WriteLine($"Committed regions: {committedRegions.Count}");
    Console.WriteLine("Base address        Region size     State    Protection          Type     Allocation base");

    foreach (var region in committedRegions.Take(80))
    {
        Console.WriteLine(
            $"0x{region.BaseAddress:X16}  0x{region.RegionSize:X12}  {region.State,-7} " +
            $"{region.Protection,-19} {region.Type,-8} 0x{region.AllocationBase:X16}");
    }

    if (committedRegions.Count > 80)
    {
        Console.WriteLine($"... {committedRegions.Count - 80} committed regions not displayed.");
    }

    var rawRegion = RawVirtualMemoryQuery.QueryFirstRegion(processId);
    Console.WriteLine();
    Console.WriteLine($"Raw LibraryImport MEMORY_BASIC_INFORMATION example: base 0x{rawRegion.BaseAddress:X16}, size 0x{rawRegion.RegionSize:X}.");
}
catch (MemoryInspectionException exception)
{
    Console.Error.WriteLine($"Memory inspection failed: {exception.Operation}; Win32 error {exception.NativeErrorCode} ({exception.Message})");
}
