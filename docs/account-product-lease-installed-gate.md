# Agent preproduction account-product JWS Open gate

**Owner:** Licensing Agent: machine trust and execution. **Issuer:** Digital Solutions.

Pinned DS source: `09c16bc5c7e1d6ab3cb8df0ba569e6da05498f3f`.
Pinned immutable library: `@bke/licensing v0.10.0`, source `b39fa5cc28c94c87a40a420e80f387c176564144`, tarball SHA-256 `4d2f8e4295effcfd4aa3b6492944e8dbba3ec75e86c83727a30daa74e4f75d60`.

## Runtime behavior and independent license keys

The installed Agent Host enables this JWS account-product OPEN gate only when `BKE_ACCOUNT_PRODUCT_LEASE_GATE_ENABLED=1` AND `BKE_ENVIRONMENT` is `development`, `certification` or `utm`. Default is OFF. Production with gate enabled terminates at bootstrap. Existing commercial license-key activation is unchanged where the preproduction gate is off.

With the gate enabled, every Launcher-mediated standalone `/v1/software/open` request needs a fresh signed DS `OPEN` lease after catalog/entitlement and installed-inventory checks, before the existing launch provider is called. No per-product setting can bypass it. Unavailable issuer, absent protected machine receipt, expired session, failed signature, or mismatched identity prevents execution. No cached lease is accepted.

This is only the **Launcher-mediated Open gate**; it is not authorization for launching an executable by another Windows process. A later distinct product-level enforcement intent is required. Source-only DS issuance is disabled in production.

## Installed trust anchor

The trusted public-only issuer bundle is located at:

    C:\Program Files\BKE Digital Solutions\Licensing Agent\trust\account-product-lease-keys\issuers.json

Bundle fields: `schema` = `bke.account-product-lease-trust.v1`, `issuer_source_sha` = pinned DS source above, `library_archive_sha256` = pinned tarball above, and `keys` array with `kid`, `public_key_pem` (real SPKI Ed25519 PUBLIC key), and `state` (ACTIVE or VERIFY_ONLY). Exactly one ACTIVE key is required. **No private key or placeholder is valid.**

The key bundle is never loaded from an environment variable, Launcher IPC, catalog, product manifest, remote key advertisement, or unprotected ProgramData. The runtime validates the canonical installed Program Files root, missing/reparse-point components, bounded bundle, unique fields/kids, Ed25519 public key, state, pinned DS and library provenance. The privileged installer may optionally copy a separately authorized public bundle from `dist/windows/account-product-lease-keys/issuers.json`. Builds do not synthesize or activate signer trust automatically.

The installer already replaces and rolls back its `{app}\trust` directory with its runtime. This optional trust bundle uses the same privileged lifecycle.

## Proof and release locks

Minimum declared certification: Agent `contracts`, `windows-x64`, `installer`, `rollback`, `acquisition`, `utm-trust`, `fraction-lease` (pinned immutable library source). No DS/library CI duplication.

No production signer/key provisioning, production DB migration, deployment, PayMongo/Resend, production signing cutover, installer/catalog/release publication, or customer activation is authorized by this source-only wave.
