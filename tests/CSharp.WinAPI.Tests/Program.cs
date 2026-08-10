using CSharp.WinAPI.LocalGroups;
using CSharp.WinAPI.Memory;
using CSharp.WinAPI.Modules;
using CSharp.WinAPI.Pe;
using CSharp.WinAPI.Processes;
using CSharp.WinAPI.Threads;

var failures = new List<string>();
var inspector = new LocalGroupInspector();

Run("local-group enumeration returns named groups", () =>
{
    var groups = inspector.EnumerateLocalGroups();
    Assert(groups.Count > 0, "No local groups were returned.");
    Assert(groups.All(group => !string.IsNullOrWhiteSpace(group.Name)), "A group had no name.");
});

Run("members can be read for an enumerated group", () =>
{
    var group = inspector.EnumerateLocalGroups().First();
    var members = inspector.EnumerateMembers(group.Name);
    Assert(members.All(member => !string.IsNullOrWhiteSpace(member.SidUsage)), "A member had no SID usage.");
});

Run("an invalid local group preserves the native error", () =>
{
    const string missingGroup = "CSharpWinApi-Definitely-Not-A-Local-Group";

    try
    {
        _ = inspector.EnumerateMembers(missingGroup);
        throw new InvalidOperationException("The API unexpectedly found the deliberately invalid group.");
    }
    catch (NetApiException exception)
    {
        Assert(
            exception.NativeErrorCode is 1376 or 2220,
            $"Expected ERROR_NO_SUCH_ALIAS (1376) or NERR_GroupNotFound (2220), got {exception.NativeErrorCode}.");
    }
});

var processInspector = new ProcessInspector();

Run("process enumeration contains the current process", () =>
{
    var processes = processInspector.EnumerateProcesses();
    Assert(processes.Any(process => process.ProcessId == (uint)Environment.ProcessId), "The current process was absent from the snapshot.");
});

Run("current process has core inspection data", () =>
{
    var process = processInspector.InspectProcess((uint)Environment.ProcessId);
    Assert(process.ProcessId == (uint)Environment.ProcessId, "The inspected PID did not match the current process.");
    Assert(!string.IsNullOrWhiteSpace(process.Name), "The current process had no executable name.");
    Assert(!string.IsNullOrWhiteSpace(process.ExecutablePath), "The current process had no executable path.");
    Assert(process.CreationTimeUtc is not null, "The current process had no creation time.");
    Assert(process.SessionId is not null, "The current process had no session ID.");
    Assert(process.Architecture is not null, "The current process architecture was unavailable.");
});

Run("invalid process IDs are reported", () =>
{
    try
    {
        _ = processInspector.InspectProcess(uint.MaxValue);
        throw new InvalidOperationException("The impossible PID was unexpectedly present in the snapshot.");
    }
    catch (ProcessInspectionException exception)
    {
        Assert(exception.NativeErrorCode == 1168, $"Expected ERROR_NOT_FOUND (1168), got {exception.NativeErrorCode}.");
    }
});

Run("process inspection can be repeated without retaining handles", () =>
{
    for (var iteration = 0; iteration < 3; iteration++)
    {
        var processes = processInspector.EnumerateProcesses();
        Assert(processes.Count > 0, "Process enumeration returned no entries.");
    }
});

var threadInspector = new ThreadInspector();

Run("thread enumeration returns at least one thread", () =>
{
    Assert(threadInspector.EnumerateThreads().Count > 0, "No threads were returned.");
});

Run("current process threads expose core Toolhelp data", () =>
{
    var currentProcessId = (uint)Environment.ProcessId;
    var threads = threadInspector.EnumerateProcessThreads(currentProcessId);
    Assert(threads.Count > 0, "The current process had no threads in the snapshot.");
    Assert(threads.All(thread => thread.ThreadId > 0), "A current-process thread had an invalid ID.");
    Assert(threads.All(thread => thread.ProcessId == currentProcessId), "Thread filtering returned another process's thread.");
    Assert(threads.All(thread => thread.BasePriority is >= 0 and <= 31), "A base priority was outside the THREADENTRY32 range.");
});

Run("invalid process thread filtering returns no entries", () =>
{
    Assert(threadInspector.EnumerateProcessThreads(uint.MaxValue).Count == 0, "The impossible PID unexpectedly had threads.");
});

Run("thread inspection can be repeated without retaining snapshot handles", () =>
{
    for (var iteration = 0; iteration < 3; iteration++)
    {
        Assert(threadInspector.EnumerateThreads().Count > 0, "Thread enumeration returned no entries.");
    }
});

var moduleInspector = new ModuleInspector();

Run("current process module enumeration returns complete entries", () =>
{
    var currentProcessId = (uint)Environment.ProcessId;
    var modules = moduleInspector.EnumerateProcessModules(currentProcessId);
    Assert(modules.Count > 0, "The current process had no modules.");
    Assert(modules.All(module => !string.IsNullOrWhiteSpace(module.ModuleName)), "A module had no name.");
    Assert(modules.All(module => module.ProcessId == currentProcessId), "A module belonged to another process.");
    Assert(modules.All(module => module.BaseAddress > 0), "A module had an invalid base address.");
    Assert(modules.All(module => module.ModuleSize > 0), "A module had an invalid size.");
    Assert(
        modules.All(module => string.IsNullOrWhiteSpace(module.ModulePath) || Path.IsPathFullyQualified(module.ModulePath)),
        "A non-empty module path was not fully qualified.");

    if (!string.IsNullOrWhiteSpace(Environment.ProcessPath))
    {
        Assert(
            modules.Any(module => string.Equals(module.ModulePath, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)),
            "The current executable image was absent from its module list.");
    }
});

Run("invalid module process IDs preserve a native failure", () =>
{
    try
    {
        _ = moduleInspector.EnumerateProcessModules(uint.MaxValue);
        throw new InvalidOperationException("The impossible PID unexpectedly returned a module list.");
    }
    catch (ModuleInspectionException exception)
    {
        Assert(exception.NativeErrorCode != 0, "The module failure did not preserve a Win32 error code.");
    }
});

Run("module inspection can be repeated without retaining snapshot handles", () =>
{
    for (var iteration = 0; iteration < 3; iteration++)
    {
        Assert(moduleInspector.EnumerateProcessModules((uint)Environment.ProcessId).Count > 0, "Module enumeration returned no entries.");
    }
});

var memoryInspector = new VirtualMemoryInspector();

Run("virtual-memory enumeration returns regions", () =>
{
    Assert(memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId).Count > 0, "No virtual-memory regions were returned.");
});

Run("virtual-memory regions have positive sizes", () =>
{
    var regions = memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId);
    Assert(regions.All(region => region.RegionSize > 0), "A virtual-memory region had zero size.");
});

Run("virtual-memory base addresses use pointer-sized values", () =>
{
    var regions = memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId);
    Assert(IntPtr.Size is 4 or 8, "The runtime did not report a supported pointer size.");
    Assert(regions.All(region => region.BaseAddress <= nuint.MaxValue), "A base address could not be represented as nuint.");
});

Run("virtual-memory size values are representable", () =>
{
    var regions = memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId);
    Assert(
        regions.All(region => region.BaseAddress <= nuint.MaxValue - region.RegionSize),
        "A region end address overflowed the pointer-sized address range.");
});

Run("virtual-memory states are documented values", () =>
{
    var regions = memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId);
    Assert(
        regions.All(region => region.State is MemoryState.Commit or MemoryState.Reserve or MemoryState.Free),
        "A region had an unknown state value.");
});

Run("virtual-memory protection flags retain valid raw values", () =>
{
    const uint knownProtectionBits =
        (uint)(MemoryProtection.NoAccess |
               MemoryProtection.ReadOnly |
               MemoryProtection.ReadWrite |
               MemoryProtection.WriteCopy |
               MemoryProtection.Execute |
               MemoryProtection.ExecuteRead |
               MemoryProtection.ExecuteReadWrite |
               MemoryProtection.ExecuteWriteCopy |
               MemoryProtection.Guard |
               MemoryProtection.NoCache |
               MemoryProtection.WriteCombine |
               MemoryProtection.TargetsInvalid);
    var regions = memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId);
    var committed = regions.Where(region => region.State == MemoryState.Commit).ToList();

    Assert(committed.Count > 0, "The current process had no committed memory regions.");
    Assert(committed.All(region => (region.RawProtection & ~knownProtectionBits) == 0), "A committed region had unknown protection bits.");
    Assert(committed.All(region => region.RawProtection == (uint)region.Protection), "Protection flags were not preserved exactly.");
});

Run("virtual-memory types retain valid raw values", () =>
{
    var regions = memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId);
    Assert(
        regions.All(region => region.Type is MemoryType.None or MemoryType.Private or MemoryType.Mapped or MemoryType.Image),
        "A region had an unknown type value.");
    Assert(regions.All(region => region.RawType == (uint)region.Type), "Type values were not preserved exactly.");
});

Run("virtual-memory traversal terminates", () =>
{
    var regions = memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId);
    Assert(regions.Count < 100_000, "Virtual-memory traversal exceeded the expected finite region count.");
});

Run("virtual-memory regions do not overlap or duplicate", () =>
{
    var regions = memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId);

    for (var index = 0; index < regions.Count - 1; index++)
    {
        var current = regions[index];
        var next = regions[index + 1];
        Assert(current.BaseAddress + current.RegionSize <= next.BaseAddress, "Virtual-memory regions overlapped or were duplicated.");
    }
});

Run("invalid virtual-memory process IDs preserve a native failure", () =>
{
    try
    {
        _ = memoryInspector.EnumerateProcessMemory(uint.MaxValue);
        throw new InvalidOperationException("The impossible PID unexpectedly returned virtual-memory metadata.");
    }
    catch (MemoryInspectionException exception)
    {
        Assert(exception.Operation == "OpenProcess", $"Expected OpenProcess to fail, got {exception.Operation}.");
        Assert(exception.NativeErrorCode != 0, "The memory failure did not preserve a Win32 error code.");
    }
});

Run("virtual-memory inspection can be repeated without retaining handles", () =>
{
    for (var iteration = 0; iteration < 3; iteration++)
    {
        Assert(memoryInspector.EnumerateProcessMemory((uint)Environment.ProcessId).Count > 0, "Virtual-memory enumeration returned no regions.");
    }
});

var peInspector = new PeImageInspector();

Run("PE32 fixture parses deterministically", () => WithPeFixture(pe32Plus: false, path =>
{
    var image = peInspector.Inspect(path);
    Assert(image.Format == PeImageFormat.Pe32, "The PE32 fixture was not detected as PE32.");
    Assert(image.ImageBase == 0x00400000, "The PE32 image base was incorrect.");
}));

Run("PE32+ fixture parses deterministically", () => WithPeFixture(pe32Plus: true, path =>
{
    var image = peInspector.Inspect(path);
    Assert(image.Format == PeImageFormat.Pe32Plus, "The PE32+ fixture was not detected as PE32+.");
    Assert(image.ImageBase == 0x0000000140000000, "The PE32+ image base was incorrect.");
}));

Run("PE parser validates MZ signature", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    bytes[0] = 0;
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "DOS header");
}));

Run("PE parser validates PE signature", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    bytes[0x80] = 0;
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "PE header");
}));

Run("PE parser preserves known and unknown machine values", () => WithPeFixture(pe32Plus: true, path =>
{
    var image = peInspector.Inspect(path);
    Assert(image.Machine == 0x8664 && image.Architecture == PeMachineArchitecture.Amd64, "AMD64 was not detected.");
    var bytes = File.ReadAllBytes(path);
    WriteUInt16(bytes, 0x84, 0xFFFF);
    File.WriteAllBytes(path, bytes);
    image = peInspector.Inspect(path);
    Assert(image.Machine == 0xFFFF && image.Architecture == PeMachineArchitecture.Unknown, "An unknown machine was not preserved.");
}));

Run("PE parser detects optional-header format", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt16(bytes, 0x98, 0x7777);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Optional header");
}));

Run("PE parser exposes section headers", () => WithPeFixture(pe32Plus: false, path =>
{
    var section = peInspector.Inspect(path).Sections.Single();
    Assert(section.Name == ".text", "The deterministic section name was incorrect.");
    Assert(section.VirtualAddress == 0x1000 && section.PointerToRawData == 0x200, "The deterministic section mapping was incorrect.");
    Assert(section.Characteristics.HasFlag(PeSectionCharacteristics.MemoryExecute), "The executable section characteristic was missing.");
}));

Run("PE parser exposes data directories", () => WithPeFixture(pe32Plus: false, path =>
{
    var directories = peInspector.Inspect(path).DataDirectories;
    Assert(directories.Count == 16, "The standard data-directory table was incomplete.");
    Assert(directories[0].Kind == PeDataDirectoryKind.ExportTable && directories[0].Address == 0x1000, "The export directory was incorrect.");
    Assert(directories[4].AddressIsFileOffset, "The certificate directory was not marked as a file offset.");
}));

Run("PE RVA mapping handles headers sections and invalid RVAs", () => WithPeFixture(pe32Plus: false, path =>
{
    var image = peInspector.Inspect(path);
    Assert(image.GetFileOffsetForRva(0x100) == 0x100, "Header RVA mapping was incorrect.");
    Assert(image.GetFileOffsetForRva(0x1010) == 0x210, "Section RVA mapping was incorrect.");
    Assert(!image.TryGetFileOffsetForRva(0x1200, out _), "An RVA beyond raw data mapped unexpectedly.");
    AssertPeFailure(() => image.GetFileOffsetForRva(0x1200), "RVA mapping");
}));

Run("PE parser rejects truncated images", () => WithPeFixture(pe32Plus: false, path =>
{
    File.WriteAllBytes(path, File.ReadAllBytes(path).Take(0x90).ToArray());
    AssertPeFailure(() => peInspector.Inspect(path), "PE header");
}));

Run("PE parser rejects overflowing header offsets", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x3C, uint.MaxValue);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "PE header");
}));

Run("PE parser rejects invalid section raw-data bounds", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x178 + 20, 0xFFFF0000);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Section raw data");
}));

Run("PE parser rejects empty and invalid paths", () =>
{
    AssertPeFailure(() => peInspector.Inspect(string.Empty), "Path");
    AssertPeFailure(() => peInspector.Inspect(Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.exe")), "Path");
});

return failures.Count == 0 ? 0 : 1;

void Run(string name, Action test)
{
    try
    {
        test();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception exception)
    {
        failures.Add(name);
        Console.Error.WriteLine($"FAIL {name}: {exception.Message}");
    }
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

static void WithPeFixture(bool pe32Plus, Action<string> test)
{
    var path = Path.Combine(Path.GetTempPath(), $"CSharp-WinAPI-PeFixture-{Guid.NewGuid():N}.bin");
    File.WriteAllBytes(path, BuildPeFixture(pe32Plus));

    try
    {
        test(path);
    }
    finally
    {
        File.Delete(path);
    }
}

static void AssertPeFailure(Action action, string expectedStage)
{
    try
    {
        action();
        throw new InvalidOperationException("The malformed PE unexpectedly parsed successfully.");
    }
    catch (PeImageInspectionException exception)
    {
        Assert(exception.Stage == expectedStage, $"Expected PE failure at {expectedStage}, got {exception.Stage}.");
    }
}

static byte[] BuildPeFixture(bool pe32Plus)
{
    var image = new byte[0x400];
    image[0] = (byte)'M';
    image[1] = (byte)'Z';
    WriteUInt32(image, 0x3C, 0x80);
    WriteUInt32(image, 0x80, 0x00004550);
    var coffOffset = 0x84;
    WriteUInt16(image, coffOffset, pe32Plus ? (ushort)0x8664 : (ushort)0x014C);
    WriteUInt16(image, coffOffset + 2, 1);
    WriteUInt32(image, coffOffset + 4, 1_700_000_000);
    WriteUInt16(image, coffOffset + 16, pe32Plus ? (ushort)0xF0 : (ushort)0xE0);
    WriteUInt16(image, coffOffset + 18, 0x0002);
    var optionalOffset = 0x98;
    WriteUInt16(image, optionalOffset, pe32Plus ? (ushort)0x020B : (ushort)0x010B);
    image[optionalOffset + 2] = 14;
    image[optionalOffset + 3] = 29;
    WriteUInt32(image, optionalOffset + 4, 0x200);
    WriteUInt32(image, optionalOffset + 8, 0x200);
    WriteUInt32(image, optionalOffset + 16, 0x1000);
    WriteUInt32(image, optionalOffset + 20, 0x1000);
    if (pe32Plus)
    {
        WriteUInt64(image, optionalOffset + 24, 0x0000000140000000);
    }
    else
    {
        WriteUInt32(image, optionalOffset + 24, 0x2000);
        WriteUInt32(image, optionalOffset + 28, 0x00400000);
    }

    WriteUInt32(image, optionalOffset + 32, 0x1000);
    WriteUInt32(image, optionalOffset + 36, 0x200);
    WriteUInt32(image, optionalOffset + 56, 0x2000);
    WriteUInt32(image, optionalOffset + 60, 0x200);
    WriteUInt16(image, optionalOffset + 68, 3);
    WriteUInt16(image, optionalOffset + 70, 0x0140);
    var sizeOffset = pe32Plus ? 72 : 72;
    if (pe32Plus)
    {
        WriteUInt64(image, sizeOffset, 0x100000);
        WriteUInt64(image, sizeOffset + 8, 0x1000);
        WriteUInt64(image, sizeOffset + 16, 0x100000);
        WriteUInt64(image, sizeOffset + 24, 0x1000);
        WriteUInt32(image, optionalOffset + 108, 16);
    }
    else
    {
        WriteUInt32(image, sizeOffset, 0x100000);
        WriteUInt32(image, sizeOffset + 4, 0x1000);
        WriteUInt32(image, sizeOffset + 8, 0x100000);
        WriteUInt32(image, sizeOffset + 12, 0x1000);
        WriteUInt32(image, optionalOffset + 92, 16);
    }

    var directoryOffset = optionalOffset + (pe32Plus ? 112 : 96);
    WriteUInt32(image, directoryOffset, 0x1000);
    WriteUInt32(image, directoryOffset + 4, 0x20);
    WriteUInt32(image, directoryOffset + 8, 0x1020);
    WriteUInt32(image, directoryOffset + 12, 0x20);
    WriteUInt32(image, directoryOffset + (4 * 8), 0x300);
    WriteUInt32(image, directoryOffset + (4 * 8) + 4, 0x40);
    var sectionOffset = optionalOffset + (pe32Plus ? 0xF0 : 0xE0);
    ".text"u8.CopyTo(image.AsSpan(sectionOffset, 5));
    WriteUInt32(image, sectionOffset + 8, 0x180);
    WriteUInt32(image, sectionOffset + 12, 0x1000);
    WriteUInt32(image, sectionOffset + 16, 0x200);
    WriteUInt32(image, sectionOffset + 20, 0x200);
    WriteUInt32(image, sectionOffset + 36, 0x60000020);
    return image;
}

static void WriteUInt16(byte[] buffer, int offset, ushort value) => System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), value);

static void WriteUInt32(byte[] buffer, int offset, uint value) => System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset), value);

static void WriteUInt64(byte[] buffer, int offset, ulong value) => System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset), value);
