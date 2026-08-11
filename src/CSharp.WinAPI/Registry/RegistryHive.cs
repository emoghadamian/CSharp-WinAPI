namespace CSharp.WinAPI.Registry;
/// <summary>Supported local predefined registry hives.</summary>
public enum RegistryHive
{
    /// <summary>HKEY_CLASSES_ROOT.</summary>
    ClassesRoot = 0,

    /// <summary>HKEY_CURRENT_USER.</summary>
    CurrentUser = 1,

    /// <summary>HKEY_LOCAL_MACHINE.</summary>
    LocalMachine = 2,

    /// <summary>HKEY_USERS.</summary>
    Users = 3,

    /// <summary>HKEY_CURRENT_CONFIG.</summary>
    CurrentConfig = 4,
}
