namespace CSharp.WinAPI.Registry;
/// <summary>Selects the registry view used when opening a key.</summary>
public enum RegistryView
{
    /// <summary>Use the process default registry view.</summary>
    Default = 0,

    /// <summary>Use the 32-bit registry view.</summary>
    Registry32 = 1,

    /// <summary>Use the 64-bit registry view.</summary>
    Registry64 = 2,
}
