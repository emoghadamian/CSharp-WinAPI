namespace CSharp.WinAPI.Pe;

/// <summary>Read-only metadata for one aligned WIN_CERTIFICATE entry.</summary>
public sealed record PeCertificateInfo(uint Length, ushort Revision, ushort CertificateType, uint PayloadOffset, uint PayloadLength, IReadOnlyList<PeX509CertificateInfo>? Certificates, int? SignerCount, string? DigestAlgorithm)
{
    /// <summary>Gets the recognized revision when known.</summary>
    public PeCertificateRevision? KnownRevision => Enum.IsDefined(typeof(PeCertificateRevision), Revision) ? (PeCertificateRevision)Revision : null;
    /// <summary>Gets the recognized certificate type when known.</summary>
    public PeCertificateType? KnownCertificateType => Enum.IsDefined(typeof(PeCertificateType), CertificateType) ? (PeCertificateType)CertificateType : null;
}
