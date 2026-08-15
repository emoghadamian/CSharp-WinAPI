using System.Runtime.InteropServices;
namespace ScheduledTaskInspection;
// Explicit COM lifetime contrast: all objects are released in finally blocks and no task mutation members are called.
internal static class RawScheduledTask
{
    internal static string DescribeFirstTask()
    {
        var hr = CoInitializeEx(nint.Zero, 2); var uninitialize = hr >= 0; if (hr < 0 && hr != unchecked((int)0x80010106)) Marshal.ThrowExceptionForHR(hr);
        object? service = null; object? folder = null; object? tasks = null; object? task = null;
        try { service = Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("0F87369F-A4E5-4CFC-BD3E-73E6154572DD"))!) ?? throw new InvalidOperationException(); ((dynamic)service).Connect(); folder = ((dynamic)service).GetFolder("\\"); tasks = ((dynamic)folder).GetTasks(1); if ((int)((dynamic)tasks).Count == 0) return "no root tasks"; task = ((dynamic)tasks)[1]; return $"{((dynamic)task).Path}: state={((dynamic)task).State}, enabled={((dynamic)task).Enabled}"; }
        finally { Release(task); Release(tasks); Release(folder); Release(service); if (uninitialize) CoUninitialize(); }
    }
    private static void Release(object? value) { if (value is not null && Marshal.IsComObject(value)) _ = Marshal.FinalReleaseComObject(value); }
    [DllImport("ole32.dll", EntryPoint = "CoInitializeEx")] private static extern int CoInitializeEx(nint reserved, uint coInit);
    [DllImport("ole32.dll", EntryPoint = "CoUninitialize")] private static extern void CoUninitialize();
}
