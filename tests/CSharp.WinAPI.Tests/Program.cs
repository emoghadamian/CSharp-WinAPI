using CSharp.WinAPI.LocalGroups;
using CSharp.WinAPI.Memory;
using CSharp.WinAPI.Modules;
using CSharp.WinAPI.Pe;
using CSharp.WinAPI.Processes;
using CSharp.WinAPI.Threads;
using CSharp.WinAPI.Tokens;

var FixedCms = Convert.FromBase64String("MIIExwYJKoZIhvcNAQcCoIIEuDCCBLQCAQExDTALBglghkgBZQMEAgEwEgYJKoZIhvcNAQcBoAUEAwECA6CCAw4wggMKMIIB8qADAgECAggdZs60nr5UFTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNQmx1ZVRlYW0gTGFiczEeMBwGA1UEAxMVQ1NoYXJwLVdpbkFQSSBGaXh0dXJlMB4XDTI0MDEwMTAwMDAwMFoXDTMwMDEwMTAwMDAwMFowRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUJsdWVUZWFtIExhYnMxHjAcBgNVBAMTFUNTaGFycC1XaW5BUEkgRml4dHVyZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOn7dkQvMA146Z5D97EEquUMv93h0bRqGSApRY34kRS7wC2K2vjIZ3rqKUnU8Z1l7g2uO+97HQvwIrMG8dSCfpVeIcgV108U03FQsx+qxSXbm9NaVDVa4tMf1ez96wbCC2sJyV0tzAurYKRTefBY4D/BgVJiUKpXYYxQmr3CZ+4mYUitBZOeAdPCtnEG8b/OP9XEfmlfHoi4nhMIfe82OyTtFHmERxxFcb/PmlaEgpwtxf4nw0UP2st/k1aIcQ7gQF0eBQIEt+X0qMvv4jWrOYs979cwGq90nqwva9DwrseCJxc019eTKeVaGkmqm+xdAdeTazAUa5kL1JDRuGphrp0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAMu/QKioJWUCEolVX6j/GqYx3P7o6tZ/HyixjVNN6qwkDZTg4Mlz9T9d6usTFFbCXLujMBJI4EFWvN4MoeJsYaSuhf8N1Ok+TkoypWrNn+TKLlkLAjIjUTX01PKWYfqB1F6f0f9KmjCykrhgNQUwcYyCnP38R0H26cGzNyRK5ph7XutM4fXpLGbOw8hjQ5nUdlFhChS+A7cw0KoV8ez5sjdRIvUBZNp6nxBvNJurreHaYlAvV/0Q78/x+FuT76Xv7Y6sdJZYxBcgGuMOxx9LVITRVQmcdDVz2+03UBM4dPLpad25qIQLs0NBOl2Du1vuo6+ECEml2abg5rvkdm9FmXzGCAXgwggF0AgEBMFEwRTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUJsdWVUZWFtIExhYnMxHjAcBgNVBAMTFUNTaGFycC1XaW5BUEkgRml4dHVyZQIIHWbOtJ6+VBUwCwYJYIZIAWUDBAIBMAsGCSqGSIb3DQEBAQSCAQB2rWkuriJPPD/L+KNmdT5tRbMH8UcLMkxFZWfyadR2qK6BtQauZ/pBBj3VTuLyC1/RJGM6q5m7S1T6a6TOU06pzE7qHyu1NiaAyeOX8hJUdHR/L1UK/i9sKTb6f84o4mppe3CoLQSO1FGMJdHoqYGbSX+psX/8npyPdYfJZZQEkTlI7S32kNSBl878vV3OQO8TlEMolxTLN1KpZR00Qn6EDpuqhPckyS3Rcnw1FWao2C3Q0OUOzXgxU/H+dBKZJRfoBx0+fE8SsBb/FrW8/1PBiQr6W1R4jnMaYFvHnsEbL+1cdkpTK+TZNFaUiLd9r2HFGi6Mzi0lWimlcU+4VEC2");

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

var tokenInspector = new TokenInspector();

Run("current process token exposes read-only identity and security metadata", () =>
{
    var token = tokenInspector.InspectCurrentProcessToken();
    var process = processInspector.InspectProcess((uint)Environment.ProcessId);
    Assert(token.ProcessId == (uint)Environment.ProcessId, "The token PID did not match the current process.");
    Assert(!string.IsNullOrWhiteSpace(token.User.Sid), "The token user SID was empty.");
    Assert(token.Groups.Count > 0, "The token contained no groups.");
    Assert(token.Privileges.Count > 0, "The token contained no privileges.");
    Assert(!string.IsNullOrWhiteSpace(token.IntegrityLevel.Sid), "The token integrity SID was empty.");
    Assert(process.SessionId is not null && token.SessionId == process.SessionId.Value, "The token session did not match the current process session.");
    Assert(token.Type.Value == TokenType.Primary, "The current process did not expose a primary token.");
    Assert(token.ImpersonationLevel is null, "A primary token unexpectedly exposed an impersonation level.");
});

Run("invalid token process IDs preserve contextual native errors", () =>
{
    try
    {
        _ = tokenInspector.InspectProcessToken(uint.MaxValue);
        throw new InvalidOperationException("The impossible PID unexpectedly had a token.");
    }
    catch (TokenInspectionException exception)
    {
        Assert(exception.ProcessId == uint.MaxValue, "The token exception did not preserve the target PID.");
        Assert(exception.Operation == "OpenProcess", $"Expected OpenProcess, got {exception.Operation}.");
        Assert(exception.NativeErrorCode != 0, "The token exception lost the native error code.");
    }
});

Run("token inspection can be repeated without retaining handles", () =>
{
    for (var iteration = 0; iteration < 100; iteration++)
    {
        var token = tokenInspector.InspectCurrentProcessToken();
        Assert(!string.IsNullOrWhiteSpace(token.User.Sid), "Repeated token inspection returned no user SID.");
    }
});

Run("token collections are immutable snapshots", () =>
{
    var token = tokenInspector.InspectCurrentProcessToken();
    AssertCollectionSnapshot(token.Groups, "token groups");
    AssertCollectionSnapshot(token.Privileges, "token privileges");
});

Run("token models retain unknown native enum values", () =>
{
    var type = new TokenTypeInfo(uint.MaxValue, TokenType.Unknown);
    var level = new TokenImpersonationLevelInfo(uint.MaxValue, TokenImpersonationLevel.Unknown);
    Assert(type.RawValue == uint.MaxValue && type.Value == TokenType.Unknown, "An unknown token type lost its raw value.");
    Assert(level.RawValue == uint.MaxValue && level.Value == TokenImpersonationLevel.Unknown, "An unknown impersonation level lost its raw value.");
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
    Assert(directories[0].Kind == PeDataDirectoryKind.ExportTable && directories[0].Address == 0x1200, "The export directory was incorrect.");
    Assert(directories[4].AddressIsFileOffset, "The certificate directory was not marked as a file offset.");
}));

Run("PE public collections are immutable snapshots", () =>
{
    WithPeFixture(pe32Plus: false, path =>
    {
        var image = peInspector.Inspect(path);
        AssertCollectionSnapshot(image.Sections, "section headers");
        AssertCollectionSnapshot(image.DataDirectories, "data directories");
        AssertCollectionSnapshot(image.Exports!.Functions, "export functions");
    }, includeImports: true);
    WithPeFixture(pe32Plus: false, path =>
    {
        var module = peInspector.Inspect(path).Imports.First();
        AssertCollectionSnapshot(peInspector.Inspect(path).Imports, "import modules");
        AssertCollectionSnapshot(module.Functions, "import functions");
    }, includeImports: true);
    WithCertificateFixture(FixedCms, path =>
    {
        var table = peInspector.Inspect(path).CertificateTable!;
        AssertCollectionSnapshot(table.Entries, "certificate entries");
        AssertCollectionSnapshot(table.Entries[0].Certificates!, "CMS certificates");
    });
});

Run("PE parser permits boundary-touching raw RVA ranges", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    AddSectionHeader(bytes, pe32Plus: false, name: ".data", virtualAddress: 0x1400, virtualSize: 0x200, sizeOfRawData: 0x200, pointerToRawData: 0x400);
    File.WriteAllBytes(path, bytes);
    var image = peInspector.Inspect(path);
    Assert(image.Sections.Count == 2, "The boundary-touching section was not retained.");
    Assert(image.GetFileOffsetForRva(0x1410) == 0x410, "The boundary-touching section did not map deterministically.");
}));

Run("PE parser rejects overlapping raw RVA section ranges", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    AddSectionHeader(bytes, pe32Plus: false, name: ".over", virtualAddress: 0x1300, virtualSize: 0x200, sizeOfRawData: 0x200, pointerToRawData: 0x400);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Section table");
}));

Run("PE parser rejects malformed section RVA ranges", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x184, 0x100);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Section table");
    bytes = BuildPeFixture(pe32Plus: false);
    WriteUInt32(bytes, 0x184, uint.MaxValue);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Section table");
}));

Run("PE RVA mapping handles headers sections and invalid RVAs", () => WithPeFixture(pe32Plus: false, path =>
{
    var image = peInspector.Inspect(path);
    Assert(image.GetFileOffsetForRva(0x100) == 0x100, "Header RVA mapping was incorrect.");
    Assert(image.GetFileOffsetForRva(0x1010) == 0x210, "Section RVA mapping was incorrect.");
    Assert(!image.TryGetFileOffsetForRva(0x1400, out _), "An RVA beyond raw data mapped unexpectedly.");
    AssertPeFailure(() => image.GetFileOffsetForRva(0x1400), "RVA mapping");
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

Run("PE32 import fixture resolves multiple modules and functions", () => WithPeFixture(pe32Plus: false, path =>
{
    var imports = peInspector.Inspect(path).Imports;
    Assert(imports.Count == 2, "The PE32 import fixture did not expose two DLLs.");
    Assert(imports[0].Name == "KERNEL32.dll" && imports[0].Functions.Count == 2, "The first PE32 import module was incorrect.");
    Assert(imports[1].Name == "ADVAPI32.dll" && imports[1].Functions.Single().Name == "RegOpenKeyExW", "The second PE32 import module was incorrect.");
}, includeImports: true));

Run("PE32+ import fixture uses 64-bit thunk values", () => WithPeFixture(pe32Plus: true, path =>
{
    var firstImport = peInspector.Inspect(path).Imports.Single(module => module.Name == "KERNEL32.dll");
    Assert(firstImport.Functions[0].Name == "CreateFileW", "The PE32+ name import was incorrect.");
    Assert(firstImport.Functions[0].LookupTableRva == 0x1140 && firstImport.Functions[0].ImportAddressTableRva == 0x1160, "The PE32+ thunk RVAs were incorrect.");
}, includeImports: true));

Run("PE imports retain names hints and ordinal imports", () => WithPeFixture(pe32Plus: false, path =>
{
    var functions = peInspector.Inspect(path).Imports.Single(module => module.Name == "KERNEL32.dll").Functions;
    Assert(functions[0].Name == "CreateFileW" && functions[0].Hint == 0x1234 && !functions[0].IsOrdinal, "The import-by-name metadata was incorrect.");
    Assert(functions[1].Name is null && functions[1].Ordinal == 5 && functions[1].IsOrdinal && functions[1].Hint is null, "The import-by-ordinal metadata was incorrect.");
}, includeImports: true));

Run("PE parser rejects an invalid import directory RVA", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x100, 0xFFFF0000);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Import directory");
}, includeImports: true));

Run("PE parser rejects a truncated import descriptor table", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x104, 20);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Import directory");
}, includeImports: true));

Run("PE parser rejects an unterminated import DLL name", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    Array.Fill(bytes, (byte)'A', 0x380, 0x280);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Import DLL name");
}, includeImports: true));

Run("PE parser rejects an unterminated thunk table", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x310, 0x1140);

    for (var offset = 0x340; offset < 0x600; offset += 4)
    {
        WriteUInt32(bytes, offset, 0x1190);
    }

    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Import lookup table");
}, includeImports: true));

Run("PE parser rejects an invalid import hint/name RVA", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x340, 0x7FFF0000);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Import hint/name");
}, includeImports: true));

Run("PE parser detects delay-import metadata without merging it", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x98 + 96 + (13 * 8), 0x1100);
    WriteUInt32(bytes, 0x98 + 96 + (13 * 8) + 4, 0x20);
    File.WriteAllBytes(path, bytes);
    var image = peInspector.Inspect(path);
    Assert(image.HasDelayImports, "The delay-import directory was not detected.");
    Assert(image.Imports.Count == 2, "Delay imports were incorrectly merged with normal imports.");
}, includeImports: true));

Run("PE32 export fixture parses deterministically", () => WithPeFixture(pe32Plus: false, path =>
{
    var exports = peInspector.Inspect(path).Exports;
    Assert(exports is not null && exports.Name == "fixture.dll", "The PE32 export DLL name was incorrect.");
    Assert(exports!.NumberOfFunctions == 3 && exports.NumberOfNames == 2, "The PE32 export counts were incorrect.");
}));

Run("PE32+ export fixture parses deterministically", () => WithPeFixture(pe32Plus: true, path =>
{
    var exports = peInspector.Inspect(path).Exports;
    Assert(exports is not null && exports.Functions.Count == 3, "The PE32+ export table was not parsed.");
}));

Run("PE exports distinguish named and ordinal-only functions", () => WithPeFixture(pe32Plus: false, path =>
{
    var functions = peInspector.Inspect(path).Exports!.Functions;
    Assert(functions[0].Name == "NamedOne" && functions[0].IsNamed && functions[0].AddressRva == 0x1010, "The named export was incorrect.");
    Assert(functions[2].Name is null && !functions[2].IsNamed && functions[2].AddressRva is null, "The ordinal-only export was incorrect.");
}));

Run("PE exports apply a non-zero ordinal base", () => WithPeFixture(pe32Plus: false, path =>
{
    var functions = peInspector.Inspect(path).Exports!.Functions;
    Assert(functions.Select(function => function.Ordinal).SequenceEqual(new uint[] { 10, 11, 12 }), "Public ordinals did not apply the ordinal base.");
}));

Run("PE exports detect named and ordinal forwarded functions", () => WithPeFixture(pe32Plus: false, path =>
{
    var functions = peInspector.Inspect(path).Exports!.Functions;
    Assert(functions[1].IsForwarded && functions[1].ForwarderName == "NTDLL.ForwardOne" && functions[1].AddressRva is null, $"The named forwarded export was incorrect: {functions[1]}.");
    Assert(functions[2].IsForwarded && functions[2].ForwarderName == "KERNEL32.ForwardTwo", "The ordinal forwarded export was incorrect.");
}));

Run("PE parser rejects an invalid export directory RVA", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0xF8, 0xFFFF0000);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Export directory");
}));

Run("PE parser rejects an invalid export function table RVA", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x41C, 0xFFFF0000);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Export address table");
}));

Run("PE parser rejects invalid export name pointers and ordinal indexes", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x450, 0xFFFF0000);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Export name");
    bytes = BuildPeFixture(pe32Plus: false);
    WriteUInt16(bytes, 0x460, 3);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Export ordinal table");
}));

Run("PE parser rejects unterminated and truncated export directories", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    Array.Fill(bytes, (byte)'A', 0x470, 0x190);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Export DLL name");
    bytes = BuildPeFixture(pe32Plus: false);
    WriteUInt32(bytes, 0xFC, 20);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Export directory");
}));

Run("PE parser rejects overflowing public export ordinals", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    WriteUInt32(bytes, 0x410, uint.MaxValue);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Export address table");
}));

Run("unsigned PE has no certificate table", () => WithPeFixture(pe32Plus: false, path =>
{
    Assert(peInspector.Inspect(path).CertificateTable is null, "An unsigned fixture unexpectedly had a certificate table.");
}));

Run("PE certificate table uses direct file offsets and preserves unknown types", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = File.ReadAllBytes(path);
    Array.Resize(ref bytes, 0x608);
    WriteUInt32(bytes, 0x118, 0x600);
    WriteUInt32(bytes, 0x11C, 8);
    WriteUInt32(bytes, 0x600, 8);
    WriteUInt16(bytes, 0x604, 0x0200);
    WriteUInt16(bytes, 0x606, 0x9999);
    File.WriteAllBytes(path, bytes);
    var table = peInspector.Inspect(path).CertificateTable;
    Assert(table is not null && table.FileOffset == 0x600 && table.EntryCount == 1, "Certificate Table was not read as a direct file offset.");
    var entry = table!.Entries.Single();
    Assert(entry.PayloadOffset == 0x608 && entry.PayloadLength == 0 && entry.KnownRevision == PeCertificateRevision.Revision2 && entry.KnownCertificateType is null, "WIN_CERTIFICATE metadata was incorrect.");
}));

Run("PE certificate table parses the fixed public CMS fixture exactly", () => WithCertificateFixture(FixedCms, path =>
{
    var table = peInspector.Inspect(path).CertificateTable!;
    var entry = table.Entries.Single();
    Assert(entry.KnownRevision == PeCertificateRevision.Revision2 && entry.KnownCertificateType == PeCertificateType.PkcsSignedData, "The fixed CMS WIN_CERTIFICATE header was incorrect.");
    Assert(entry.PayloadOffset == 0x608 && entry.PayloadLength == FixedCms.Length, "The fixed CMS payload bounds were incorrect.");
    Assert(entry.SignerCount == 1 && !string.IsNullOrWhiteSpace(entry.DigestAlgorithm), "SignedCms signer metadata was not exposed.");
    var certificate = entry.Certificates!.Single();
    Assert(certificate.Subject == "CN=CSharp-WinAPI Fixture, O=BlueTeam Labs, C=US", "The fixture subject changed.");
    Assert(certificate.Issuer == "CN=CSharp-WinAPI Fixture, O=BlueTeam Labs, C=US", "The fixture issuer changed.");
    Assert(certificate.SerialNumber == "1D66CEB49EBE5415", "The fixture serial changed.");
    Assert(certificate.Thumbprint == "49563851834AFBF57B8D31E5BE2785D21322FCD5", "The fixture thumbprint changed.");
    Assert(certificate.NotBefore.ToUniversalTime() == new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc), "The fixture NotBefore changed.");
    Assert(certificate.NotAfter.ToUniversalTime() == new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), "The fixture NotAfter changed.");
    Assert(certificate.SignatureAlgorithm == "sha256RSA", "The fixture signature algorithm changed.");
    Assert(certificate.PublicKeyAlgorithm == "RSA", "The fixture public-key algorithm changed.");
}));

Run("PE certificate table supports aligned multiple entries", () => WithCertificateFixture(FixedCms, path =>
{
    var bytes = File.ReadAllBytes(path);
    var firstLength = 8 + FixedCms.Length;
    var secondOffset = Align8(0x600 + firstLength);
    Array.Resize(ref bytes, secondOffset + 8);
    WriteUInt32(bytes, secondOffset, 8);
    WriteUInt16(bytes, secondOffset + 4, 0x0100);
    WriteUInt16(bytes, secondOffset + 6, 0x9999);
    WriteUInt32(bytes, 0x11C, (uint)(secondOffset + 8 - 0x600));
    File.WriteAllBytes(path, bytes);
    var table = peInspector.Inspect(path).CertificateTable!;
    Assert(table.EntryCount == 2, "Aligned certificate entries were not both parsed.");
    Assert(table.Entries[1].PayloadOffset == secondOffset + 8 && table.Entries[1].KnownRevision == PeCertificateRevision.Revision1 && table.Entries[1].KnownCertificateType is null, "The second certificate entry was incorrect.");
}));

Run("PE certificate table rejects invalid WIN_CERTIFICATE lengths", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = BuildCertificateFixture(new byte[0]);
    WriteUInt32(bytes, 0x600, 0);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Certificate table");
    bytes = BuildCertificateFixture(new byte[0]);
    WriteUInt32(bytes, 0x600, 7);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Certificate table");
}));

Run("PE certificate table rejects truncated and out-of-bounds data", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = BuildCertificateFixture(new byte[] { 0xAA }, certificateType: 0x9999);
    WriteUInt32(bytes, 0x600, 17);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Certificate table");
    bytes = BuildCertificateFixture(new byte[0], certificateType: 0x9999);
    WriteUInt32(bytes, 0x11C, 12);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Certificate table");
    bytes = BuildPeFixture(pe32Plus: false);
    WriteUInt32(bytes, 0x118, 0x700);
    WriteUInt32(bytes, 0x11C, 8);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Certificate table");
}));

Run("PE certificate table rejects invalid alignment and malformed later entries", () => WithPeFixture(pe32Plus: false, path =>
{
    var bytes = BuildCertificateFixture(new byte[] { 0xAA }, certificateType: 0x9999);
    WriteUInt32(bytes, 0x11C, 9);
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Certificate table");
    bytes = BuildCertificateFixture(FixedCms);
    var secondOffset = Align8(0x600 + 8 + FixedCms.Length);
    Array.Resize(ref bytes, secondOffset + 8);
    WriteUInt32(bytes, secondOffset, 0);
    WriteUInt32(bytes, 0x11C, (uint)(secondOffset + 8 - 0x600));
    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Certificate table");
}));

Run("PE certificate table bounds its entry count", () => WithPeFixture(pe32Plus: false, path =>
{
    const int entryCount = 4_097;
    var bytes = BuildPeFixture(pe32Plus: false);
    Array.Resize(ref bytes, 0x600 + (entryCount * 8));
    WriteUInt32(bytes, 0x118, 0x600);
    WriteUInt32(bytes, 0x11C, entryCount * 8);

    for (var index = 0; index < entryCount; index++)
    {
        var offset = 0x600 + (index * 8);
        WriteUInt32(bytes, offset, 8);
        WriteUInt16(bytes, offset + 4, 0x0200);
        WriteUInt16(bytes, offset + 6, 0x9999);
    }

    File.WriteAllBytes(path, bytes);
    AssertPeFailure(() => peInspector.Inspect(path), "Certificate table");
}));

Run("PE certificate table reports malformed PKCS7 context", () => WithCertificateFixture(new byte[] { 1, 2, 3 }, path =>
{
    AssertPeFailure(() => peInspector.Inspect(path), "PKCS#7");
}));

Run("PE example displays unsigned and fixed certificate-bearing fixtures", () =>
{
    WithPeFixture(pe32Plus: false, path =>
    {
        var output = RunPeExample(path);
        Assert(output.Contains("Certificate Table:"), "The PE example omitted the Certificate Table section.");
        Assert(output.Contains("Present: No"), "The PE example did not identify the unsigned fixture.");
    });
    WithCertificateFixture(FixedCms, path =>
    {
        var output = RunPeExample(path);
        Assert(output.Contains("Present: Yes"), "The PE example did not identify the certificate-bearing fixture.");
        Assert(output.Contains("CN=CSharp-WinAPI Fixture, O=BlueTeam Labs, C=US"), "The PE example did not display the fixture identity.");
        Assert(output.Contains("1D66CEB49EBE5415") && output.Contains("49563851834AFBF57B8D31E5BE2785D21322FCD5"), "The PE example did not display the exact fixture serial and thumbprint.");
        Assert(output.Contains("do not establish signature validity, trust, or file safety"), "The PE example did not state its trust limitation.");
    });
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

static void AssertCollectionSnapshot<T>(IReadOnlyList<T> values, string description)
{
    Assert(values is not T[], $"The {description} collection exposed its backing array.");
    Assert(values is IList<T> list && list.IsReadOnly, $"The {description} collection was not read-only.");

    try
    {
        ((IList<T>)values)[0] = values[0];
        throw new InvalidOperationException($"The {description} collection accepted a mutation.");
    }
    catch (NotSupportedException)
    {
    }
}

static void WithPeFixture(bool pe32Plus, Action<string> test, bool includeImports = false)
{
    var path = Path.Combine(Path.GetTempPath(), $"CSharp-WinAPI-PeFixture-{Guid.NewGuid():N}.bin");
    File.WriteAllBytes(path, BuildPeFixture(pe32Plus, includeImports));

    try
    {
        test(path);
    }
    finally
    {
        File.Delete(path);
    }
}

static void WithCertificateFixture(byte[] payload, Action<string> test)
{
    WithPeFixture(pe32Plus: false, path =>
    {
        File.WriteAllBytes(path, BuildCertificateFixture(payload));
        test(path);
    });
}

static byte[] BuildCertificateFixture(byte[] payload, ushort certificateType = (ushort)PeCertificateType.PkcsSignedData)
{
    const int tableOffset = 0x600;
    var length = checked(8 + payload.Length);
    var tableSize = Align8(length);
    var image = BuildPeFixture(pe32Plus: false);
    Array.Resize(ref image, tableOffset + tableSize);
    WriteUInt32(image, 0x118, tableOffset);
    WriteUInt32(image, 0x11C, (uint)tableSize);
    WriteUInt32(image, tableOffset, (uint)length);
    WriteUInt16(image, tableOffset + 4, 0x0200);
    WriteUInt16(image, tableOffset + 6, certificateType);
    payload.CopyTo(image.AsSpan(tableOffset + 8));
    return image;
}

static int Align8(int value) => checked((value + 7) & ~7);

static string RunPeExample(string path)
{
    var assemblyPath = Path.GetFullPath(Path.Combine("examples", "pe", "PeInspection", "bin", "Debug", "net8.0-windows", "PeInspection.dll"));
    var dotnetHost = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
    var startInfo = new System.Diagnostics.ProcessStartInfo(dotnetHost, $"\"{assemblyPath}\" \"{path}\"")
    {
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true,
    };
    using var process = System.Diagnostics.Process.Start(startInfo) ?? throw new InvalidOperationException("The PE example could not be started.");
    var output = process.StandardOutput.ReadToEnd();
    var error = process.StandardError.ReadToEnd();
    process.WaitForExit();
    Assert(process.ExitCode == 0, $"The PE example failed: {error}");
    return output;
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

static byte[] BuildPeFixture(bool pe32Plus, bool includeImports = false)
{
    var image = new byte[0x600];
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
    WriteUInt32(image, directoryOffset, 0x1200);
    WriteUInt32(image, directoryOffset + 4, 0xA0);
    if (includeImports)
    {
        WriteUInt32(image, directoryOffset + 8, 0x1100);
        WriteUInt32(image, directoryOffset + 12, 0x3C);
    }
    var sectionOffset = optionalOffset + (pe32Plus ? 0xF0 : 0xE0);
    ".text"u8.CopyTo(image.AsSpan(sectionOffset, 5));
    WriteUInt32(image, sectionOffset + 8, 0x400);
    WriteUInt32(image, sectionOffset + 12, 0x1000);
    WriteUInt32(image, sectionOffset + 16, 0x400);
    WriteUInt32(image, sectionOffset + 20, 0x200);
    WriteUInt32(image, sectionOffset + 36, 0x60000020);
    if (includeImports)
    {
        AddImportFixtureData(image, pe32Plus);
    }

    AddExportFixtureData(image);

    return image;
}

static void AddSectionHeader(byte[] image, bool pe32Plus, string name, uint virtualAddress, uint virtualSize, uint sizeOfRawData, uint pointerToRawData)
{
    var coffOffset = 0x84;
    var optionalOffset = 0x98;
    var sectionOffset = optionalOffset + (pe32Plus ? 0xF0 : 0xE0);
    var additionalSectionOffset = sectionOffset + 40;
    WriteUInt16(image, coffOffset + 2, 2);
    System.Text.Encoding.ASCII.GetBytes(name).AsSpan(0, Math.Min(name.Length, 8)).CopyTo(image.AsSpan(additionalSectionOffset, 8));
    WriteUInt32(image, additionalSectionOffset + 8, virtualSize);
    WriteUInt32(image, additionalSectionOffset + 12, virtualAddress);
    WriteUInt32(image, additionalSectionOffset + 16, sizeOfRawData);
    WriteUInt32(image, additionalSectionOffset + 20, pointerToRawData);
    WriteUInt32(image, additionalSectionOffset + 36, 0xC0000040);
}

static void AddExportFixtureData(byte[] image)
{
    WriteUInt32(image, 0x400, 0xCAFEBABE);
    WriteUInt32(image, 0x404, 1_700_000_001);
    WriteUInt16(image, 0x408, 1);
    WriteUInt16(image, 0x40A, 2);
    WriteUInt32(image, 0x40C, 0x1270);
    WriteUInt32(image, 0x410, 10);
    WriteUInt32(image, 0x414, 3);
    WriteUInt32(image, 0x418, 2);
    WriteUInt32(image, 0x41C, 0x1240);
    WriteUInt32(image, 0x420, 0x1250);
    WriteUInt32(image, 0x424, 0x1260);
    WriteUInt32(image, 0x440, 0x1010);
    WriteUInt32(image, 0x444, 0x1280);
    WriteUInt32(image, 0x448, 0x1292);
    WriteUInt32(image, 0x450, 0x12C0);
    WriteUInt32(image, 0x454, 0x12D0);
    WriteUInt16(image, 0x460, 0);
    WriteUInt16(image, 0x462, 1);
    "fixture.dll\0"u8.CopyTo(image.AsSpan(0x470));
    "NTDLL.ForwardOne\0"u8.CopyTo(image.AsSpan(0x480));
    "KERNEL32.ForwardTwo\0"u8.CopyTo(image.AsSpan(0x492));
    "NamedOne\0"u8.CopyTo(image.AsSpan(0x4C0));
    "ForwardNamed\0"u8.CopyTo(image.AsSpan(0x4D0));
}

static void AddImportFixtureData(byte[] image, bool pe32Plus)
{
    var width = pe32Plus ? 8 : 4;
    WriteUInt32(image, 0x300, 0x1140);
    WriteUInt32(image, 0x304, 0x11111111);
    WriteUInt32(image, 0x308, 0xFFFFFFFF);
    WriteUInt32(image, 0x30C, 0x1180);
    WriteUInt32(image, 0x310, 0x1160);
    WriteUInt32(image, 0x314, 0x11A0);
    WriteUInt32(image, 0x320, 0x11C0);
    WriteUInt32(image, 0x324, 0x11B0);
    WriteThunk(image, 0x340, 0x1190, pe32Plus);
    WriteThunk(image, 0x340 + width, pe32Plus ? 0x8000000000000005UL : 0x80000005UL, pe32Plus);
    WriteThunk(image, 0x360, 0x1190, pe32Plus);
    WriteThunk(image, 0x360 + width, pe32Plus ? 0x8000000000000005UL : 0x80000005UL, pe32Plus);
    WriteThunk(image, 0x3A0, 0x11D0, pe32Plus);
    WriteThunk(image, 0x3B0, 0x11D0, pe32Plus);
    "KERNEL32.dll\0"u8.CopyTo(image.AsSpan(0x380));
    WriteUInt16(image, 0x390, 0x1234);
    "CreateFileW\0"u8.CopyTo(image.AsSpan(0x392));
    "ADVAPI32.dll\0"u8.CopyTo(image.AsSpan(0x3C0));
    WriteUInt16(image, 0x3D0, 4);
    "RegOpenKeyExW\0"u8.CopyTo(image.AsSpan(0x3D2));
}

static void WriteUInt16(byte[] buffer, int offset, ushort value) => System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), value);

static void WriteUInt32(byte[] buffer, int offset, uint value) => System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset), value);

static void WriteUInt64(byte[] buffer, int offset, ulong value) => System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset), value);

static void WriteThunk(byte[] buffer, int offset, ulong value, bool pe32Plus)
{
    if (pe32Plus)
    {
        WriteUInt64(buffer, offset, value);
    }
    else
    {
        WriteUInt32(buffer, offset, (uint)value);
    }
}
