# Agent Ed25519 machine-key custody — scoped certification wave

Parent: https://github.com/jan2xo/bke-digital-solutions/issues/340

## Intent
Generate and durably protect a **software** Ed25519 private key inside the Licensing Agent on Windows, export canonical Ed25519 SPKI PEM, and sign only exact `bke.agent-key-proof.v1` ENROLL/LEASE challenge bytes from the certified Digital Solutions #345 source. No public API, product authorization, TPM attestation, production use or software release in this wave.

## Fixed source checkpoints
- Agent main/base: `da4efd3553d0c94db820b4e1282381b8b3ab5a37`
- Digital Solutions #345 (source-only, draft): `bd184f3f1f6399125c12df448e9e07a4ae35f875`, 6/6 certification PASS
- DS challenge authority: `apps/web/agent-sessions/agent-key-proof-authority.ts` at the above SHA.
- Agent #118/#119/#120 and library #90 stay independent unmerged drafts.

## Security policy and scope
- Windows user-scoped DPAPI protected software Ed25519 seed. No TPM, hardware attestation, or nonexportability claim.
- Local private key never transmitted, logged or written to plaintext disk; decrypted key exists transiently in process memory during signing.
- **Fail closed** for macOS/Linux until separately certified protected-key stores exist.
- Store is bound to the authenticated Agent session/account/user/device identity supplied by a trusted internal caller. The unsigned OS fingerprint is not cryptographic machine identity.
- No general-purpose signing API. Only strict newline-delimited DS protocol envelope, with context-match and nonce/purpose/product/action validation, may be signed.
- Corruption, unreadable protected state, wrong identity, malformed challenge and canceled work deny without silently replacing key.
- Local reset cannot revoke DS registration; authenticated DS revocation must be separately integrated before production rotation/re-enrollment.

## BKE CERTIFICATION PLAN
Required: `contracts` + `windows-x64` on exact current Agent head, explicitly via trusted `/certify contracts windows-x64`.
- `contracts`: .NET solution and source invariants across platforms.
- `windows-x64`: actual Windows DPAPI persistence, Ed25519 SPKI/thumbprint, exact DS byte signing, negative matrix, restart, corruption, identity mismatch and removal.
Not required: installer, rollback, UTM, acquisition, self-update, fraction-lease, DS/Library/Launcher/Render Dock full CI, payments/providers, software release.
Cross-repo proof: immutable DS #345 source SHA and its prior 6/6 key-PoP proof only. This wave proves the Agent's locally protected signer, **not** actual HTTP delivery to DS.
Risk: New signing/private-key custody is machine-security owned; Windows must execute cryptographic key-storage integration tests, Linux-only contracts cannot certify it.

Current status: initial durable wave ledger; implementation and exact-head CI pending. DRAFT / DO NOT MERGE. Production, publishing, release/signing cutover locked.
