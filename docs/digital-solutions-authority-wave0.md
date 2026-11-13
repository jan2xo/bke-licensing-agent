# Wave 0 — Digital Solutions HTTPS authority convergence (Agent consumer)

**Canonical owner:** [Digital Solutions #340](https://github.com/jan2xo/bke-digital-solutions/issues/340), Wave 0.

**Scope:** Preproduction-only Agent source migration toward the **existing** Digital Solutions authority at `https://bkedigitalsolutions.com` (chosen because the stable `api.` hostname has not been provisioned or verified). `BKE_PLATFORM_BASE_URL` remains configurable and version-independent. One default is used across Agent HTTPS remotes. UTM refuses all BKE production origins, not only `jl-bke.com`. This PR does **not** deploy, merge, publish, sign or change DNS.

**Source checkpoint:** DS main `888202f39ac4650b522fc2ed052557cdc9ee924f`, Agent base `e41cf1f2d69378f9ff326bab2a85dc7ba26dea1f`, Launcher main `7354c3730fafe65deff5ecd811ac558baa2d0c0f`.

## Reconciled API reality
- `GET /keys` **already exists on DS**: `app/keys/route.ts` re-exports `app/api/licensing/keys/route.ts`. Do not create duplicate key endpoints; retain Agent's existing trusted-key parsing and certificate/key-ID checks.
- Account session: `/api/agent-sessions/device/start|token`, `refresh`, `catalog`, `provision/standalone`, `update/standalone` are present on DS. Agent already consumes the modern DS account-based product update route via `StandaloneUpdateAuthorizationRemote`.
- Agent **self-update** `GET /api/licensing-agent/update` is implemented separately in DS.
- Legacy **product** updater `UpdateProvider` and `PrivilegedUpdateCenterProvider` still call `POST /api/agent/updates/check`, requiring a legacy signed `bke.update-policy.v1` with artifact hash/revision/download URL. The existing DS account-based standalone update endpoint issues `bke.update-policy.v2` with GitHub release tag and NO direct hash/download URL. **Not wire-compatible.** Do NOT fabricate conversion or bypass signature/provenance; this legacy consumer remains blocked pending a separate signed contract migration with DS-owned adapter or explicit replacement. These old operations fail closed when DS returns 404.
- Legacy password/MFA and customer-entered license-key activation are not part of the new Google-only session licensing design; this PR does not reenact obsolete DS endpoints.

## Security non-regression
- No automatic credential-bearing HTTP redirects, no production-origin access from UTM.
- No DS source duplication, no local entitlement issuer, no store/pricing modifications.
- Preserve separate product Update and Repair semantics, signed release provenance, key and token secrecy, DPAPI storage, and credential custody.
- No production cutover or legacy host retirement until downstream clients and provider flows are independently certified, and human owner explicitly authorizes release.

## Certification plan (exact final PR head to be recorded)
- Required Agent: `contracts`, `windows-x64`, `utm-trust`, `acquisition`, `self-update` because the HTTPS authority affects account and standalone product remotes, disposable test separation, and signed Agent self-update fetching. Self-update proof pins exact DS SHA via `ds:<sha>`.
- Not required: Installer/Defender/rollback/preflight, Launcher UI or new DS workflow. No privileged packaging/reboot behavior or DS source was changed. Source-only checks are not installed acceptance proof.
- Cross-repo proof: pin DS `888202f39ac4650b522fc2ed052557cdc9ee924f` for interface inventory; this source-only PR is not proof of installed Agent↔DS acceptance.
- No merge per owner instruction; PR remains draft/open even if CI is green.

## Remaining gates after this PR
1. Certify exact current Agent head against current DS and observed owned endpoints; review legacy product update consumers as separate substantive contract wave.
2. Issue DS account-session-authenticated signed product leases in #340 Wave 1; add product verifier and golden vectors.
3. Perform actual disposable installed Google → catalog → lease → Render Dock lifecycle acceptance.
4. Explicitly authorize any production distribution or host cutover later.
