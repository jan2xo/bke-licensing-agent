# Privileged standalone startup machine proof — PREPRODUCTION

Parent [issue #130](https://github.com/jan2xo/bke-licensing-agent/issues/130). Agent base `5cf43d00c09cbeb42932ec5875ce45e3bd6989ee`, DS source `9633ca81d706f3f8001391a815fdacc0597981b2`.

## Ownership and trust limits
- Existing user-DPAPI Ed25519 account-session key and privileged updater signing key MUST NOT be reused for installation attestation.
- Only an **elevated, installed Windows Agent provisioner**, explicitly enabled for `development`, `certification` or `utm`, may create a distinct machine-DPAPI-protected Ed25519 startup key or sign an installed target attestation.
- The public registration object contains `kid`, `deviceId` and canonical Ed25519 `publicKeyPem` only. It is a *candidate* for a separately authenticated, admin-controlled DS database registration. **Never auto-insert or accept a request-supplied key into DS trust.**
- Product ID / entry point must match a previously signed, privileged target policy, and its actual binary hash must be recomputed from the protected Windows installation root. The caller may not supply image paths, hashes or a key.
- The attestation only asserts privileged installed-machine facts; it cannot replace DS SQL product mode, authenticated account JWS or independent signed commercial lease. It does not authorize customer startup.
- No public HTTP/IPC issuance or background signing listener; no product credential handling, no Google account required for key-only license products.
- Windows built-in administrator/SYSTEM process is the local trust boundary for this preproduction source-only wave. Missing privileged install or signer makes all claims unavailable.
- No actual production key material, customer enrollment, DS deployment or installer/release publication. `BKE_ENVIRONMENT=production` and default unset flags deny.

## DS envelope (pinned exact SHA)
DS `standalone-startup-install-attestation.ts` requires canonical UTF-8 JSON envelope fields in order: `schema`, `kid`, `payload`, `signature`; inner payload fields in order: `schema`, `product_id`, `version`, `installation_id`, `image_path`, `image_sha256`, `allowed_user_sid`, `device_id`, `attestation_id`, `issued_at`, `expires_at`. Sign with Ed25519 over UTF-8 `BKE-AGENT-STARTUP-INSTALL-ATTESTATION-V1\n` + exact payload. Standard canonical padded base64 signature; UTC dates with three fractional decimals and Z. DS accepts only separately registered ACTIVE key and burns UUID once in SERIALIZABLE SQL transaction.

## Explicit certification ownership
- Agent exact-head `contracts windows-x64 installer acquisition rollback utm-trust` initially required due new privileged signing key and target provenance.
- `self-update fraction-lease preflight` excluded unless changed signing/verifier/release ownership requires widening.
- Cross-repo pin DS `9633ca81d706f3f8001391a815fdacc0597981b2`; verify signing contract with DS public verifier before customer acceptance.
- Product/SDK/Launcher integration belongs to separate intents. Production locked.
