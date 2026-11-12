# L1 signed lease fraction-to-fraction certification

Status: source-only interoperability certification; no package release, production activity, or change to live launch authorization.

Owner: Licensing Agent contracts; source authority: Digital Solutions issue #340.

Producer: real @bke/licensing TypeScript Ed25519 signer at library PR #90 SHA 28f08cd07071d00194dd672c6f186dd628e9803a (merged source-only, unreleased).
Consumer: real standalone Agent .NET verifier at the exact current Agent draft PR head.
Canonical 14-case synthetic fixture stdout SHA-256: 1e4fefe9df64dd2b0313a7b127c850417659a092647e515411a6595900802d80.

The existing Agent Intent Certification workflow adds an explicit fraction-lease target. It checks out both full commit SHAs, runs the real TypeScript signer with a PUBLIC TEST-ONLY seed, passes signed JWS bytes unchanged to the .NET verifier, and asserts all 14 pinned vectors plus fresh signer integration negatives. It records exact-SHA PASS/FAIL evidence as an artifact.

Use the existing trusted default-branch Intent Certification router with `/certify contracts fraction-lease lib:28f08cd07071d00194dd672c6f186dd628e9803a` on the Agent PR. The router resolves the current exact Agent PR head and immutable upstream source. Verify both source SHAs and required PASS evidence before source-only merge.

Required: Agent contracts and fraction-lease only. Not required: Windows native, installers, UTM, acquisition, rollback, self-update, DS app, Launcher or Render Dock certification (their runtime behavior is not changed in this source-only L1 intent).

Passing L1 proves strict TypeScript-to-.NET wire compatibility, NOT actual DS entitlement issuance, TPM/nonexportable key possession, authorized Agent execution, or authentic product binary protection. These remain explicit subsequent intents.

Unmerged library PR #90 and Agent #118/#119 remain independent draft checkpoints. No consumer is repinned to an unreleased contract; no production environment is involved.
