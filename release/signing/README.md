# Release signing

This fork signs its own artifacts. No upstream signing keys are used.

| Artifact | Key material |
| --- | --- |
| Windows installers and binaries | `raw-transportation-codesign.crt` (self-signed, RSA 4096, valid until 2036-10-23) |
| Linux `.deb` / `.rpm` packages | `raw-transportation-signing.asc` |

GPG fingerprint: `2A39 910E F3EB 3444 FB32 4486 9372 B0ED 15DE 91E1`

The private half of both keys only exists as GitHub Actions secrets on this
repository (`WINDOWS_CERTIFICATES_P12`, `WINDOWS_P12_PASSWORD`, `GPG_KEY`,
`GPG_KEY_ID`, `GPG_PASSPHRASE`). When a secret is missing, the build falls back
to unsigned artifacts instead of failing.

## Verify

```bash
gpg --import raw-transportation-signing.asc
debsigs --verify package.deb     # or: rpm --checksig package.rpm
```

On Windows, importing `raw-transportation-codesign.crt` into the trusted root
store makes the signature valid locally. Because the certificate is self-signed
rather than issued by a public CA, SmartScreen still reports an unknown
publisher for everyone else.
