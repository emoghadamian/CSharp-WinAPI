namespace CSharp.WinAPI.Pe;

/// <summary>Read-only metadata for one aligned WIN_CERTIFICATE entry.</summary>
public sealed record PeCertificateInfo(uint Length, ushort Revision, ushort CertificateType, uint PayloadOffset, uint PayloadLength, IReadOnlyList<PeX509CertificateInfo>? Certificates, int? SignerCount, string? DigestAlgorithm)
{
    /// <summary>Gets an immutable snapshot of certificates embedded in the CMS payload, when applicable.</summary>
    public IReadOnlyList<PeX509CertificateInfo>? Certificates { get; } = Certificates is null ? null : PeCollectionSnapshot.Create(Certificates);

    /// <summary>Gets the recognized revision when known.</summary>
    public PeCertificateRevision? KnownRevision => Enum.IsDefined(typeof(PeCertificateRevision), Revision) ? (PeCertificateRevision)Revision : null;
    /// <summary>Gets the recognized certificate type when known.</summary>
    public PeCertificateType? KnownCertificateType => Enum.IsDefined(typeof(PeCertificateType), CertificateType) ? (PeCertificateType)CertificateType : null;
}
