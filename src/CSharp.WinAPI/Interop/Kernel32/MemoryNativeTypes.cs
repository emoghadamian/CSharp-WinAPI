using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Kernel32;

// Mirrors MEMORY_BASIC_INFORMATION. Pointer-sized fields retain the caller architecture's ABI.
[StructLayout(LayoutKind.Sequential)]
internal struct MemoryBasicInformationNative
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

// Only MaximumApplicationAddress is used by the managed traversal; the remaining fields preserve SYSTEM_INFO layout.
[StructLayout(LayoutKind.Sequential)]
internal struct SystemInfoNative
{
    internal uint OemId;
    internal uint PageSize;
    internal nint MinimumApplicationAddress;
    internal nint MaximumApplicationAddress;
    internal nuint ActiveProcessorMask;
    internal uint NumberOfProcessors;
    internal uint ProcessorType;
    internal uint AllocationGranularity;
    internal ushort ProcessorLevel;
    internal ushort ProcessorRevision;
}
