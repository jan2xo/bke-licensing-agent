# BKE live Agent ↔ DS disposable HTTP certification intent

Source base: `f7be6a7108bf9c1cc911d4be4b24176b63600065`, draft dependency (not main or release).
Master: https://github.com/jan2xo/bke-digital-solutions/issues/340

Intent: on disposable GitHub Actions compute only, execute a separate .NET consumer process using exact Agent source pinned by SHA against actual Digital Solutions machine-key HTTP route handlers exposed via loopback HTTPS with disposable PostgreSQL. Verify signed ENROLL, active metadata, authenticated REVOKE, terminal state, and unauthorized requests.

Minimum exact-head required graph: `contracts windows-x64`.
Cross-repo: exact SHA pinned in DS harness; Agent Windows DPAPI source certification remains authoritative for Windows key custody; this Linux cross-process signer is isolated to friend assembly for network contract test, never a production key store.

Security: no public listeners, no TLS validation bypass in production, no secrets/prod credentials, no real PayMongo/Resend, no published release, no Agent production registration automation, no JWS/lease product entitlement issuance. No production DB mutation or deployment. No merge while upstream draft dependencies and stolen-bearer enrollment provenance unresolved.

Not required: Commerce, payments, Launcher, installer/UTM/VM, software product binary, signing cutover, production.


## Reconciled EdDSA + ES256 exact-source contract (2026-11-12 PHT)

The disposable .NET cross-process client is a **test-only named friend assembly** with an injected ephemeral signer and synthetic session binding. It now exercises both EdDSA (software Ed25519) and ES256 (NIST P-256, 64-byte IEEE-P1363). The actual Agent production constructor and Windows signer/receipt lifecycle remain those certified under Agent #124; Linux CI does **not** attest physical TPM provenance. Do not publish this test signer, allow production DI overrides, or infer rights from its software key. DS #350 pins the exact Agent commit after this reconciliation.
