using CSharp.WinAPI.Services;
using ServiceInspection;

// Managed path: SCM inventory -> immutable ServiceInfo models. No service is opened, changed, started, or stopped.
var inspector = new ServiceInspector();
var services = inspector.EnumerateServices();

Console.WriteLine($"Services returned: {services.Count}");
Console.WriteLine("State             PID       Name                              Display name");
foreach (var service in services.OrderBy(service => service.Name, StringComparer.OrdinalIgnoreCase).Take(40))
{
    Console.WriteLine($"{service.State.Value,-17} {service.ProcessId,-9} {service.Name,-33} {service.DisplayName}");
}

if (services.Count > 40)
{
    Console.WriteLine($"... {services.Count - 40} additional services not displayed.");
}

if (args.FirstOrDefault() is { Length: > 0 } serviceName)
{
    var configuration = inspector.InspectConfiguration(serviceName);
    Console.WriteLine();
    Console.WriteLine($"Configuration for {configuration.ServiceName}");
    Console.WriteLine($"Display name: {configuration.DisplayName ?? "<null>"}");
    Console.WriteLine($"Start type: {configuration.StartType.Value} (raw {configuration.StartType.RawValue})");
    Console.WriteLine($"Binary path: {configuration.BinaryPath ?? "<null>"}");
    Console.WriteLine($"Account: {configuration.ServiceStartName ?? "<null>"}");
    Console.WriteLine($"Dependencies: {string.Join(", ", configuration.Dependencies.Select(dependency => dependency.RawName))}");
}

Console.WriteLine();
Console.WriteLine($"Raw LibraryImport example: {RawServiceInspection.DescribeFirstServiceConfiguration()}");
