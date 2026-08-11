using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace TokenInspection;

// This intentionally small example shows the buffer and handle work that TokenInspector hides.
internal static partial class RawTokenUser
{
    private const uint TokenQuery = 0x0008;
    private const int TokenUser = 1;
    private const int ErrorInsufficientBuffer = 122;

    internal static string GetCurrentUserSid()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out var token))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        try
        {
            if (GetTokenInformation(token, TokenUser, nint.Zero, 0, out var requiredLength) ||
                Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer ||
                requiredLength == 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "GetTokenInformation sizing failed.");
            }

            var buffer = Marshal.AllocHGlobal(checked((int)requiredLength));

            try
            {
                if (!GetTokenInformation(token, TokenUser, buffer, requiredLength, out var returnedLength) || returnedLength > requiredLength)
                {
                    throw new Win32Exception(Marshal.GetLastPInvokeError());
                }

                var user = Marshal.PtrToStructure<TokenUserNative>(buffer);
                return new SecurityIdentifier(user.User.Sid).Value;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            // The raw HANDLE is owned here, so this example closes it exactly once.
            _ = CloseHandle(token);
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetCurrentProcess")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint process, uint desiredAccess, out nint token);

    [LibraryImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(nint token, int informationClass, nint information, uint informationLength, out uint returnLength);

    [LibraryImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributesNative
    {
        internal nint Sid;
        internal uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUserNative
    {
        internal SidAndAttributesNative User;
    }
}
