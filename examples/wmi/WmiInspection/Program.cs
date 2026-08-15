using CSharp.WinAPI.Wmi;
using WmiInspection;
var inspector=new WmiInspector();var path=new WmiNamespacePath("ROOT\\CIMV2");
var os=inspector.QueryInstances(path,"Win32_OperatingSystem",1);Console.WriteLine($"Operating-system instances: {os.Count}");
foreach(var item in os)foreach(var property in item.Properties.Take(12))Console.WriteLine($"{property.Name} ({property.CimType}) = {property.Value ?? "<null>"}");
var service=inspector.InspectClass(path,"Win32_Service");Console.WriteLine($"Win32_Service properties: {service.Properties.Count}");
Console.WriteLine($"Raw COM concept: {RawWmiInspection.DescribeLocalNamespace()}");
