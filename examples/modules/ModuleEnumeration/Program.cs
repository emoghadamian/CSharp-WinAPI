using CSharp.WinAPI.Modules;
using ModuleEnumeration;

// Process -> module snapshot -> MODULEENTRY32 -> Module32First/Next -> managed ModuleInfo.
// A process has its executable image plus loaded DLL modules; no remote loading or mutation occurs here.
var processId = (uint)Environment.ProcessId;
var inspector = new ModuleInspector();

try
{
    var modules = inspector.EnumerateProcessModules(processId);
    Console.WriteLine($"Modules for current process ({processId}): {modules.Count}");
    Console.WriteLine("Base address        Size       PID      Name                         Path");

    foreach (var module in modules.OrderBy(module => module.BaseAddress))
    {
        Console.WriteLine(
            $"0x{module.BaseAddress:X16}  {module.ModuleSize,-10} {module.ProcessId,-8} " +
            $"{module.ModuleName,-28} {module.ModulePath}");
    }

    var rawModules = RawModuleSnapshot.ReadFirstTwoModules(processId);
    Console.WriteLine();
    Console.WriteLine($"Raw LibraryImport MODULEENTRY32 example returned {rawModules.Count} module(s).");
}
catch (ModuleInspectionException exception)
{
    Console.Error.WriteLine($"Module enumeration failed: {exception.Operation}; Win32 error {exception.NativeErrorCode} ({exception.Message})");
}
