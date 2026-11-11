# Digital Solutions #340 — Wave 0: replace obsolete product-update discovery

## Intent (one narrow executable behavior)

The Agent's user-facing `/v1/updates/check` and `/v1/update-center/open` still use the legacy signed-lease + `POST /api/agent/updates/check` (`bke.update-policy.v1`) path, which Digital Solutions does not implement. DS already serves account-session-authenticated signed `POST /api/agent-sessions/update/standalone` (`bke.update-policy.v2`), consumed by `StandaloneUpdateAuthorizationRemote` and enforced by the signed policy verifier in `PrivilegedUpdateCenterProvider.UpdateAsync`.

**Do not implement a parallel DS v1 license/signing endpoint.** Retarget the existing local update-discovery surface to this same account-authenticated DS v2 authority, and route legacy Update Center launch to the already-existing verified `SoftwareUpdateService.UpdateAsync`. Treat check-only responses as hints, *never* as authorization to execute a package. The actual update operation must reauthorize with DS and cryptographically verify the signed v2 policy/GitHub release and target before privilege.

## Versioned source baselines
- Canonical [Digital Solutions #340](https://github.com/jan2xo/bke-digital-solutions/issues/340), Wave 0 update contract.
- DS exact `888202f39ac4650b522fc2ed052557cdc9ee924f`, unchanged; no DS PR required because the necessary v2 endpoint already exists.
- Agent base main exact `e41cf1f2d69378f9ff326bab2a85dc7ba26dea1f`.
- Existing independent [Agent PR #118](https://github.com/jan2xo/bke-licensing-agent/pull/118) remains DRAFT/UNMERGED and is **not** a dependency for this patch. This branch targets current main independently; do not merge either PR.

## Safety / rejection requirements
- Sign-in is required; the Agent alone reads access token via DPAPI secret-store API and never exposes refresh token to Launcher.
- Only BKE-managed installed standalone products and exact *inventory-verified* `productId/currentVersion` may be checked. Refuse unsupported requested version, legacy installation provenance, mismatched version and missing product before contacting DS.
- DS performs account/organization/seat entitlement and release eligibility. Agent does NOT locally invent licensing decisions.
- Failed DS credential/entitlement, protocol mismatch, tamper, or transport must fail closed; invalid session clears stale local custody.
- `/v1/update-center/open` must not continue the legacy v1 download route: re-check the verified local version and delegate to the existing `SoftwareUpdateService`, which re-fetches and independently checks signed v2 release policy before performing the privileged operation.
- Preserve exact status/response contract to Launcher while returning no tokens, repo URLs, install paths or signed policy blobs on local discovery responses.

## Intentional CI plan (to be finalized at PR head)
Required Agent: `contracts`, `windows-x64`, `acquisition`, `rollback`, because the signed update discovery, privileged handoff and rollback boundary changed. Not required: `utm-trust` (no UTM machine-trust helper change), `self-update` (Agent executable self-update unchanged), `installer` and `preflight` (no installer/signing/release changes), any DS/Launcher workflow (no source changes). Proof pins DS exact SHA above; no full DS CI merely for being the consumer dependency.

**Production LOCKED.** No merge, deployment, package publishing, DNS, production DB/payment/email activity, or signing cutover. Do not describe source certification as installed Google-to-Render-Dock acceptance.
