namespace CSharp.WinAPI.Pe;

/// <summary>Public X.509 metadata extracted from an embedded CMS certificate; no private key material is exposed.</summary>
public sealed record PeX509CertificateInfo(string Subject, string Issuer, string SerialNumber, string Thumbprint, DateTime NotBefore, DateTime NotAfter, string SignatureAlgorithm, string PublicKeyAlgorithm);
