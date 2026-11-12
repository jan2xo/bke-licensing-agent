# Installed standalone startup execution gate — PREPRODUCTION

Parent: [issue #130](https://github.com/jan2xo/bke-licensing-agent/issues/130). Foundation: PR #131 merged Agent main `95170a1bab5ff253c45f3d3ad998488abdfae41f`.

## Intent
Wire the Agent Host **only when explicitly enabled in nonproduction** to a machine-local Windows named-pipe startup authorization server. A product can send a strict, identity-free startup request; the Agent obtains the connecting PID, process creation time, SID and executable SHA-256 from Windows, then applies independently verified machine trust, canonical activation mode and credential proof. Production must never accept this experimental listener.

**Critical distinction:** existing signed `bke.licensing.v3` lease proves a commercial key, not the SQL-owned product activation mode. Thus mode is never derived from mutable manifest, local SQLite, unsigned catalog cache, the product, or an env bypass. This wave uses an **offline signed DS activation-mode projection**, not live SQL issuance. No current Digital Solutions endpoint is assumed to emit one. A verified signed DS bundle must be supplied through a privileged installer before *any* direct startup can be allowed. Absent producer/signature/policy, fail closed; do not claim customer E2E is complete.

## Installed signed policy envelope
The privileged installed policy file under `{app}/trust/standalone-startup-policies/*.json` uses schema `bke.standalone-startup-policy.v1`, signed with an explicitly pinned installed DS Ed25519 issuer key using domain separation. Its payload binds product ID, version, immutable installed executable **absolute path and SHA-256**, installation ID, user SID, `ACCOUNT`/`LICENSE_KEY`/`EITHER`, `not_before`, `expires_at` and issuer source provenance. The key is **public only** and loaded from the pre-existing Program Files Agent issuer trust bundle with exact DS source/library SHA. Exact-field parsing rejects unknown/duplicate/expired/reparse paths and untrusted signatures. Ambiguous matches deny.

## Durable ledger and process pipe
The Host uses a Windows pipe ACL for LocalSystem and local users and denies remote network principals; no bearer, PID, user, product ID, installation ID, key, mode or trusted path is accepted from IPC. A bounded schema/operation/request_id request receives a fixed-format decision. Each grant commits a **unique durable SQLite row** under an OS-protected Agent directory before responding `authorized=true`; unavailable journal or duplicate PID/start/SID denies, including after service restart. Native peer identity must still match after authorization.

### Minimum complete certification graph
- **Required exact-head:** `contracts windows-x64 installer rollback acquisition utm-trust` — signed policy and mode denial matrix; Windows native pipe and Host lifecycle; installer-protected trust placement, rollback/install lifecycle, privileged ownership and UTM trust.
- **Not required:** `self-update fraction-lease preflight`, DS/Launcher suites. No DS producer/JWS verifier change, no public release signing/deployment, no Launcher code changes.
- **Cross-repo immutable:** DS `083ef5b46765384e8a442c570a0cfe746d0dc4f`, Launcher `b7dc17316574c746c570d33bc603e03b94ac5105`, previous Agent `95170a1bab5ff253c45f3d3ad998488abdfae41f`.
- **Production:** LOCKED. No real customer signer or keys, activations, public installer/release, production DB or deployment, payments/email, or force push.
- **Not claimed:** Render Dock real startup, shared SDK client, production DS signed-policy issuance, UTM human GUI. Disposable fixture tests are not customer E2E.

