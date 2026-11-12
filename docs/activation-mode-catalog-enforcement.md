# Authenticated catalog activation mode — Agent enforcement

**Producer:** Digital Solutions PR #363, merged exact main `083ef5b46765384e8a442c5700a0cfe746d0dc4f`.
**Agent base:** `bdfc0dd28ec5153c92678aef6a5f9c844255d2c1`.
**Issuer (unchanged):** Digital Solutions signed account-product JWS authority `09c16bc5c7e1d6ab3cb8df0ba569e6da05498f3f`.
**Commercial signer:** Existing independent `bke.licensing.v3` license-key lease infrastructure; no key policy changes.

The authenticated Digital Solutions `GET /api/agent-sessions/catalog` contract now requires `activation_mode` for every listed product, with exactly one of `ACCOUNT`, `LICENSE_KEY`, `EITHER`. This is derived from SQL `ProductActivationPolicy`; missing rows are not backfilled in the request, not exposed as EITHER, and cannot authorize account access.

Agent `SoftwareCatalogRemote` fails closed for missing/unknown/duplicate values and key-only account-installability contradictions. The validated mode is preserved in Agent's local software catalog as `activation_mode` so Launcher can present it. `SoftwareOpenService` and Launcher-plugin authorization allow the *account* credential only for `ACCOUNT` or `EITHER`, and still require independent entitlement, installation and any enabled signed-JWS proof; a `LICENSE_KEY` response denies account Open regardless of the entitlement flag. No per-product Launcher flag, email, or catalog row can substitute for a commercial license key.

`LICENSE_KEY` uses the independent commercial key activation/signed lease and Agent `/v1/authorize` path. The agent never silently converts a key into an account session. A future installed executable-specific/IPC gate is needed to enforce this policy against direct Windows process startup; this change does NOT claim that proof.

**Rollout:** These source-level API contract changes are coordinated with the separately certified DS producer and Launcher consumer, not deployed independently. Production remains locked: no DB mutation, deployment, signer provision, public installer release, product activation, payment/email or signing cutover.

**Certification owner:** Agent `contracts` for full type/source regressions and new strict catalog/standalone/plugin authorization matrix. Existing immutable DS producer source proof is reused. No privilege/installer/runtime-host change, so installer, rollback and UTM tests are not required for this narrow catalog enforcement.
