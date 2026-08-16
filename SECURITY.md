# Security Policy

## Scope

CSharp-WinAPI is an educational, Windows-native inspection library. Its production APIs are intentionally bounded and read-only. Security-sensitive changes should preserve internal native interop, explicit resource ownership, immutable public models, and regression coverage.

## Reporting a vulnerability

Do not publish exploitable details in a public issue before coordination. If private vulnerability reporting is enabled for this repository, use GitHub's **Security** tab to submit a private report. Otherwise, open a minimal public issue requesting a private reporting channel without including exploit details.

## Supported version

Security fixes are considered for the current `main` branch. Reports affecting intentionally deferred or out-of-scope mutation, tracing, remote-control, credential, or offensive functionality should describe the observed impact without assuming that the capability is supported.
