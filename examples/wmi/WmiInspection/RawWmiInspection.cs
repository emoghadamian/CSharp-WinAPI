using System.Management;
namespace WmiInspection;
// Explicit disposal demonstrates the COM-backed WMI wrapper lifetime; no WMI methods are invoked.
internal static class RawWmiInspection
{
    internal static string DescribeLocalNamespace(){var scope=new ManagementScope("\\\\.\\ROOT\\CIMV2");scope.Connect();using var searcher=new ManagementObjectSearcher(scope,new ObjectQuery("SELECT * FROM Win32_OperatingSystem"));using var results=searcher.Get();using var first=results.Cast<ManagementObject>().FirstOrDefault()??throw new InvalidOperationException("No operating-system instance.");return $"{first["Caption"]}: {first["Version"]}";}
}
