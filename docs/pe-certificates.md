# PE Certificate Table and Public Authenticode Metadata

The PE Certificate Table is deliberately handled separately from the other data directories. Its `VirtualAddress` field is a **file offset**, not an RVA, so the inspector never sends it through RVA-to-file-offset mapping.

```text
PE Certificate Table (file offset)
  -> WIN_CERTIFICATE (8-byte aligned entries)
    -> PKCS#7 / CMS SignedData
      -> public X.509 certificate metadata
```

## WIN_CERTIFICATE

Each entry starts with `dwLength`, `wRevision`, and `wCertificateType`, followed by the certificate payload. The inspector preserves raw revision and type values, recognizes the standard `0x0100`/`0x0200` revisions and PKCS signed-data type, and keeps unknown certificate types visible rather than discarding them. It validates table bounds, entry lengths, and eight-byte entry advancement before reading payload data.

For PKCS signed-data entries, .NET `SignedCms` decodes CMS metadata. The public result includes signer count, digest algorithm, and each embedded certificate's subject, issuer, serial number, thumbprint, validity period, signature algorithm, and public-key algorithm. This is a public-only model: private keys, certificate-store changes, network access, and file modification are not part of inspection.

## What this does not prove

```text
Certificate exists
  != CMS parses
  != Authenticode signature is cryptographically valid
  != certificate chain is trusted
  != file is safe
```

The following are intentionally deferred: Authenticode image hashing, cryptographic signature verification, certificate-chain validation, Windows trust validation, and CRL/OCSP validation. Correct Authenticode hashing has special rules for the PE CheckSum field, Certificate Table directory entry, and Certificate Table data; this project does not provide a speculative implementation.

Certificate metadata can still support publisher triage, reuse and expiry investigation, supply-chain review, and static PE analysis. A signed file is not necessarily safe, and an unsigned file is not necessarily malicious.
