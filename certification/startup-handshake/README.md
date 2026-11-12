# PREPRODUCTION exact-byte Agent → DS → Agent startup handshake

Tracking: https://github.com/jan2xo/bke-licensing-agent/issues/130

## Behavioral intent
Prove on an **ephemeral Windows runner** that actual Windows-DPAPI Agent-provisioner enrollment and privileged signed-target attestation are consumed by the pinned Digital Solutions SQL admin-registration and issuance functions in local disposable PostgreSQL, and that the actual DS-signed policy is accepted by the .NET Agent installed-policy verifier. Negative evidence covers tamper, replay, failed administrative review, and product/policy-mode mismatch. This is **certification**, not user/customer startup acceptance.

## Exact immutable sources
- Agent base: `dfbad7ba0fb37aa6ef520b6611425b13ba988044` (certified #43270749423)
- Digital Solutions source: `0be43d74d45b6a24307ddb626a6fd0d4b70bbba4` (certified #43277515014)

## Minimum complete intentional certification graph
- **Required:** `contracts windows-x64 installer rollback acquisition utm-trust startup-handshake` on the **exact final Agent PR head**, including actual Windows DPAPI/protected target, real .NET Agent → local PostgreSQL Digital Solutions two-admin and issuance → .NET Agent verifier. Broad Agent native/installer/rollback/acquisition/UTM graph is required because the integration surfaced a concrete defect in the **privileged Provisioner machine-enrollment candidate serializer**. Correctness of its published bytes and the packaged privileged helper is security-sensitive; prior #133 installer proof belongs to an earlier SHA and cannot certify changed source.
- **Not required:** `self-update fraction-lease preflight`; updater behavior, unrelated JWS runtime/TS licensing fraction and production preflight remain unchanged. No DS repo re-certification: reuse exact upstream `0be43d74d45b6a24307ddb626a6fd0d4b70bbba4` proof, and certify the changed consuming Agent interop on the exact head.
- Current integration discovery: the Agent's .NET default `JsonSerializer` public-key enrollment output escapes JSON differently from DS's strict `JSON.stringify(row) === raw` canonical public-key parser. Fix the **Agent producer** to use the same JavaScript-compatible `UnsafeRelaxedJsonEscaping` already used for the signed attestation envelope. Do not weaken DS canonical or signature checks.
- If more shared trust ownership changes are discovered, revise the graph before dispatch and keep all earlier generations stale.

## Excluded (separate intent)
No HTTP transport/public provisioning, production enrollment, human physical fingerprint attestation, signed GitHub release provenance, SDK or Render Dock customer executable startup, Launcher repin, customer acceptance or production release.

**PRODUCTION LOCKED**: no deployments, production DB, real PayMongo/Resend, production signing, installed product publication, catalog activation or force push.
