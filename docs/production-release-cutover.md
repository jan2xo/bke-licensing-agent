# BKE Licensing Agent 2.0.0 — Production Release Cutover

Status: **PRE-PRODUCTION ONLY**

This document defines the production boundary after successful Gen2 certification.

Certified Windows architecture set:

- x64 / AMD64 — Intel and AMD 64-bit Windows
- ARM64 — Windows on ARM

32-bit Windows is intentionally out of scope.

## Certified foundation

Before production cutover, the following certification phases are closed:

- Phase 7 — runtime bridge
- Phase 8 — canonical Gen2 installer migration
- Phase 9 — signed self-update pre-publication certification
- Phase 10 — broken-update rollback certification

Phase 10 includes hosted x64 rollback and persistent Windows 11 ARM64 rollback with byte-for-byte restoration.

## Phase 11 — release preflight

The Phase 11 workflow builds both canonical Gen2 Windows installers from one exact source commit:

- `BKE-Licensing-Agent-2.0.0-Windows-x64.exe`
- `BKE-Licensing-Agent-2.0.0-Windows-arm64.exe`

It then:

1. rebuilds the Gen2 bootstrap/runtime,
2. verifies x64 and ARM64 PE machine identities,
3. compiles both canonical installers,
4. scans both installers with Microsoft Defender,
5. records SHA-256 and byte size,
6. records Authenticode state,
7. emits `bke.production-release-preflight.v1`,
8. explicitly records that the artifacts are unsigned and not production-authorized.

The preflight uses disposable trust by design. Its installers MUST NOT be published to the production software catalog.

## Production cutover gates

Production release is not one action. It is the following ordered authority chain.

### Gate A — certified source convergence

Required before production signing:

- all intended Gen2 stacked PRs are reviewed and merged in dependency order,
- exact release source SHA is frozen,
- no production release is built from an unreviewed branch head,
- BKE Digital Solutions V2 signed-update authority change is reviewed and merged separately.

No production database mutation is required by the Licensing Agent release itself.

### Gate B — production update-authority key

Create a persistent Ed25519 production update-authority key through an approved protected signing boundary.

Rules:

- private key MUST NOT be committed,
- private key MUST NOT be embedded in installers,
- private key MUST NOT appear in GitHub artifacts,
- only the public key JSON is installed under `trust/update-authority-keys`,
- key ID is stable and versioned,
- rotation is explicit and monotonic.

The final installer bytes cannot be considered release-final until the production public update-authority key is embedded.

### Gate C — Windows Authenticode signing identity

Both Windows installers require the approved BKE publisher identity.

Required final state:

- x64 installer Authenticode status = `Valid`,
- ARM64 installer Authenticode status = `Valid`,
- signer subject/thumbprint matches the approved BKE code-signing certificate,
- the controlled signing process signs the intended installer bytes only,
- signed-file SHA-256 values are recomputed after signing.

Disposable/self-signed certificates do not satisfy this gate.

### Gate D — production release manifest

For the exact signed files, produce a final machine-readable release manifest containing at least:

- schema,
- source SHA,
- version,
- architecture,
- filename,
- signed SHA-256,
- byte size,
- Authenticode signer subject,
- Authenticode thumbprint,
- update-authority key ID,
- Defender result,
- certification references.

The final manifest must not reuse unsigned preflight hashes.

### Gate E — software catalog publication

Publish only the two approved signed installers:

- Windows x64,
- Windows ARM64.

The GitHub release tag and asset names must exactly match the signed update-policy contract.

No broken-update certification artifact, unsigned preflight artifact, UTM kit, or disposable-trust installer may enter the production catalog.

### Gate F — Digital Solutions V2 authority activation

Deploy the reviewed V2 signed-update authority with the complete production configuration bundle:

- latest version,
- minimum supported version,
- monotonic revision,
- production signing key ID,
- protected signing private key,
- published timestamp,
- exact x64 signed SHA-256 + size,
- exact ARM64 signed SHA-256 + size.

Partial configuration must fail closed.

### Gate G — production signed self-update acceptance

Using controlled machines:

1. install the prior supported production Agent,
2. request the production signed update policy,
3. verify the correct architecture asset is selected,
4. verify signature/hash/size binding,
5. install through the real self-update path,
6. verify service/runtime recovery,
7. verify durable licensing state,
8. verify loopback-only port 43873,
9. verify rollback remains available.

Run this for x64 and ARM64.

### Gate H — customer publication

Only after Gates A–G pass may the release be described as production.

## Explicitly prohibited before cutover authorization

- production signing-key creation or activation,
- production Authenticode signing,
- production tag/release creation,
- production software-catalog upload,
- V2 production deployment,
- update-authority environment mutation,
- merging stacked PRs without owner instruction,
- force push.

## Current boundary

Certification is complete.

The next owner-controlled boundary is:

```text
PRE-PRODUCTION RELEASE PREFLIGHT
        ↓
APPROVED PRODUCTION SIGNING IDENTITIES
        ↓
SIGNED x64 + ARM64 FINAL BYTES
        ↓
PRODUCTION CATALOG + V2 AUTHORITY
        ↓
SIGNED SELF-UPDATE ACCEPTANCE
        ↓
CUSTOMER RELEASE
```
