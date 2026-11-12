# PREPRODUCTION exact-byte Agent → DS → Agent startup handshake

Tracking: https://github.com/jan2xo/bke-licensing-agent/issues/130

## Behavioral intent
Prove on an **ephemeral Windows runner** that actual Windows-DPAPI Agent-provisioner enrollment and privileged signed-target attestation are consumed by the pinned Digital Solutions SQL admin-registration and issuance functions in local disposable PostgreSQL, and that the actual DS-signed policy is accepted by the .NET Agent installed-policy verifier. Negative evidence covers tamper, replay, failed administrative review, and product/policy-mode mismatch. This is **certification**, not user/customer startup acceptance.

## Exact immutable sources
- Agent base: `dfbad7ba0fb37aa6ef520b6611425b13ba988044` (certified #43270749423)
- Digital Solutions source: `0be43d74d45b6a24307ddb626a6fd0d4b70bbba4` (certified #43277515014)

## Minimum complete intentional certification graph
- Required: `contracts startup-handshake` against exact final PR head, including Windows DPAPI, actual .NET proof, disposable local PostgreSQL DS transaction, and actual .NET policy verification.
- Not required: Agent `installer rollback acquisition utm-trust self-update fraction-lease preflight`; no runtime/package/privileged installed application changes. No DS repo certification rerun: reuse immutable merged upstream certification; the Agent-controlled cross-repo consumer proof tests that unchanged code.
- Must amend this plan if engineering changes touch machine-trust production code, signer custody, SQL schema, runtime interface, packaging or release provenance.

## Excluded (separate intent)
No HTTP transport/public provisioning, production enrollment, human physical fingerprint attestation, signed GitHub release provenance, SDK or Render Dock customer executable startup, Launcher repin, customer acceptance or production release.

**PRODUCTION LOCKED**: no deployments, production DB, real PayMongo/Resend, production signing, installed product publication, catalog activation or force push.
