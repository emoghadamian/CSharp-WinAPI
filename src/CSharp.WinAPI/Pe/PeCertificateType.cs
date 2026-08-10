namespace CSharp.WinAPI.Pe;

/// <summary>Recognized WIN_CERTIFICATE content types.</summary>
public enum PeCertificateType : ushort
{
    /// <summary>X.509 certificate content.</summary>
    X509 = 0x0001,
    /// <summary>PKCS#7 signed-data content.</summary>
    PkcsSignedData = 0x0002,
    /// <summary>Terminal Server stack signing content.</summary>
    TsStackSigned = 0x0004,
}
