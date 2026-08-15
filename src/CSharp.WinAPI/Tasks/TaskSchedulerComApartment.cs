using System.Runtime.InteropServices;

namespace CSharp.WinAPI.Tasks;

/// <summary>Provides the narrowly scoped COM initialization needed by Task Scheduler automation.</summary>
internal sealed partial class TaskSchedulerComApartment : IDisposable
{
    private const int RpcEChangedMode = unchecked((int)0x80010106);
    private readonly bool ownsInitialization;

    private TaskSchedulerComApartment(bool ownsInitialization) => this.ownsInitialization = ownsInitialization;

    internal static TaskSchedulerComApartment Enter()
    {
        var result = CoInitializeEx(nint.Zero, 0x2); // COINIT_APARTMENTTHREADED
        if (result >= 0) return new TaskSchedulerComApartment(ownsInitialization: true);
        if (result == RpcEChangedMode) return new TaskSchedulerComApartment(ownsInitialization: false);
        Marshal.ThrowExceptionForHR(result);
        throw new InvalidOperationException("CoInitializeEx unexpectedly returned without an HRESULT.");
    }

    public void Dispose()
    {
        if (ownsInitialization) CoUninitialize();
    }

    [LibraryImport("ole32.dll", EntryPoint = "CoInitializeEx")]
    private static partial int CoInitializeEx(nint reserved, uint coInit);

    [LibraryImport("ole32.dll", EntryPoint = "CoUninitialize")]
    private static partial void CoUninitialize();
}
