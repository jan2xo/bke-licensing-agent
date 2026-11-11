# Agent machine-key first-enrollment provenance (source-only)

Upstream SHA: `bcf2616bd7ead980c905a4acf130df4eca5df385` and master checkpoint https://github.com/jan2xo/bke-digital-solutions/issues/340#issuecomment-6797838809

**Intent:** A stolen account access bearer alone SHALL NOT authorize first enrollment of a new Agent software Ed25519 machine key. Reuse the existing high-entropy device-authorization code as a separate possession secret: keep it ONLY in Agent Windows DPAPI-protected account session storage; DS checks hash against the exact consumed, approved device authorization linked to the bearer session, user, account, and device. Do not return this code in the access-token payload. Native handoff uses its existing handoff code; legacy sessions without the code fail closed for first enrollment. No TPM/device attestation claim.

**Security boundaries:** DS is authority, Agent owns protected local code and private key, Launcher owns UX. Require exact session auth + independently matched device authorization. First enrollment at most one registration per Agent session; unverified pending can retry with same local key/device code, revoked cannot silently re-register. Existing ACTIVE recovery/status does not need the code. Never leak code in logs, response, challenge or audit.

**Minimum exact-head required graph:** `contracts windows-x64` because DPAPI account secret persistence, device/native login flow and Windows cryptographic HTTP transport.

**Cross-repo proof:** pin exact DS/Agent source SHA; run actual disposable DS PostgreSQL and HTTPS route with isolated test signer plus Windows real DPAPI regression. No product/Launcher/installer/UTM/real providers/release/production. Not required: Commerce/Payments/PayMongo/Resend; JWS issuer; signing/package publication.

**Lock:** DRAFT/no merge/production locked until upstream dependencies and integrated installation risk reviewed. A thief with BOTH bearer+device code or local DPAPI compromise is not mitigated; no hardware nonexportability is claimed.
