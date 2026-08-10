namespace CSharp.WinAPI.Pe;

/// <summary>Recognized WIN_CERTIFICATE revision values.</summary>
public enum PeCertificateRevision : ushort
{
    /// <summary>Legacy version 1 certificate entry.</summary>
    Revision1 = 0x0100,
    /// <summary>Current version 2 certificate entry.</summary>
    Revision2 = 0x0200,
}
