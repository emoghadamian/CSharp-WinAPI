using CSharp.WinAPI.Etw;
using EtwProviderInspection;

var inspector = new EtwProviderInspector();
var providers = inspector.EnumerateProviders();
Console.WriteLine($"Registered ETW providers: {providers.Count}");
foreach (var provider in providers.Take(40))
    Console.WriteLine($"{provider.ProviderId}  {provider.Name}  schema={provider.RawSchemaSource}");

var microsoftProviders = inspector.FindProvidersByNamePrefix("Microsoft-Windows-");
Console.WriteLine($"Microsoft-Windows-* providers: {microsoftProviders.Count}");
Console.WriteLine($"Raw TDH example: {RawEtwProviderInspection.Describe()}");
