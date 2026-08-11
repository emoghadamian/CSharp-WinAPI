using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Interop.Kernel32;

/// <summary>Raw declarations for documented Kernel32 process-inspection APIs.</summary>
internal static partial class Kernel32Native
{
    [LibraryImport("kernel32.dll", EntryPoint = "GetCurrentProcess")]
    internal static partial nint GetCurrentProcess();
    internal const uint Th32CsSnapProcess = 0x00000002;
    internal const uint Th32CsSnapThread = 0x00000004;
    internal const uint Th32CsSnapModule = 0x00000008;
    internal const uint Th32CsSnapModule32 = 0x00000010;
    internal const int ErrorNoMoreFiles = 18;
    internal const int ErrorCallNotImplemented = 120;

    [LibraryImport("kernel32.dll", EntryPoint = "CreateToolhelp32Snapshot", SetLastError = true)]
    internal static partial SafeSnapshotHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32FirstW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Process32First(SafeSnapshotHandle snapshot, ref ProcessEntry32Native processEntry);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32NextW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Process32Next(SafeSnapshotHandle snapshot, ref ProcessEntry32Native processEntry);

    [LibraryImport("kernel32.dll", EntryPoint = "Thread32First", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Thread32First(SafeSnapshotHandle snapshot, ref ThreadEntry32Native threadEntry);

    [LibraryImport("kernel32.dll", EntryPoint = "Thread32Next", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Thread32Next(SafeSnapshotHandle snapshot, ref ThreadEntry32Native threadEntry);

    [LibraryImport("kernel32.dll", EntryPoint = "Module32FirstW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Module32First(SafeSnapshotHandle snapshot, ref ModuleEntry32Native moduleEntry);

    [LibraryImport("kernel32.dll", EntryPoint = "Module32NextW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Module32Next(SafeSnapshotHandle snapshot, ref ModuleEntry32Native moduleEntry);

    [LibraryImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
    internal static partial SafeProcessHandle OpenProcess(
        ProcessAccessRights desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [LibraryImport("kernel32.dll", EntryPoint = "VirtualQueryEx", SetLastError = true)]
    internal static partial nuint VirtualQueryEx(
        SafeProcessHandle process,
        nint address,
        out MemoryBasicInformationNative memoryInformation,
        nuint memoryInformationLength);

    [LibraryImport("kernel32.dll", EntryPoint = "GetSystemInfo")]
    internal static partial void GetSystemInfo(out SystemInfoNative systemInformation);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        char* executablePath,
        ref uint executablePathLength);

    [LibraryImport("kernel32.dll", EntryPoint = "GetProcessTimes", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetProcessTimes(
        SafeProcessHandle process,
        out FileTimeNative creationTime,
        out FileTimeNative exitTime,
        out FileTimeNative kernelTime,
        out FileTimeNative userTime);

    [LibraryImport("kernel32.dll", EntryPoint = "ProcessIdToSessionId", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [LibraryImport("kernel32.dll", EntryPoint = "IsWow64Process2", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsWow64Process2(
        SafeProcessHandle process,
        out ushort processMachine,
        out ushort nativeMachine);

    [LibraryImport("kernel32.dll", EntryPoint = "IsWow64Process", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsWow64Process(SafeProcessHandle process, out int wow64Process);

    [LibraryImport("kernel32.dll", EntryPoint = "CloseHandle")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr handle);

    [LibraryImport("kernel32.dll", EntryPoint = "LocalFree")]
    internal static partial nint LocalFree(nint memory);
}
