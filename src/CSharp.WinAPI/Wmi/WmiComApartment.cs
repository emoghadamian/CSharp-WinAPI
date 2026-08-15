using System.Runtime.InteropServices;
namespace CSharp.WinAPI.Wmi;
internal sealed partial class WmiComApartment : IDisposable
{
    private const int RpcEChangedMode = unchecked((int)0x80010106); private readonly bool owns;
    private WmiComApartment(bool owns) => this.owns = owns;
    internal static WmiComApartment Enter() { var hr = CoInitializeEx(nint.Zero, 0); if (hr >= 0) return new(true); if (hr == RpcEChangedMode) return new(false); Marshal.ThrowExceptionForHR(hr); throw new InvalidOperationException(); }
    public void Dispose() { if (owns) CoUninitialize(); }
    [LibraryImport("ole32.dll", EntryPoint="CoInitializeEx")] private static partial int CoInitializeEx(nint reserved,uint mode);
    [LibraryImport("ole32.dll", EntryPoint="CoUninitialize")] private static partial void CoUninitialize();
}
