# Handoff

This project is the foundation for the BKE Licensing Agent.

## Current state

- Python package scaffold created
- CLI scaffold created
- Manifest validation schema added
- Manifest path and semantic-version validation
- Configurable discovery with no execution during scanning
- SQLite persistence and CLI scan/list commands
- Project roadmap, changelog, environment template, and schema documentation

## Next steps

- Add structured diagnostics and duplicate-product policy
- Add secure local token storage, audit logging, and signed offline leases

## Phase 3 handoff

The typed API client foundation is implemented in `src/bke_licensing_agent/api/`.
It supports health, product, license-status, device-registration, and
license-verification contract methods. It does not authenticate users or grant
launch permission. The endpoint contract is documented in `docs/api-contract.md`.

Phase 4 authentication is implemented in `src/bke_licensing_agent/auth/`.
Authentication and session state remain separate from licensing entitlement.
The secure-storage contract is documented in `docs/secure-storage.md`.

## Phase 5 handoff

Phase 5 adds device identity, entitlement, online activation, verification, and
non-sensitive activation metadata. See `docs/device-identity.md`,
`docs/device-fingerprint.md`, `docs/license-entitlement.md`,
`docs/activation-lifecycle.md`, and `docs/local-activation-storage.md`.

Production integration and independent Phase 5 audit approval remain required.
Phase 6 must not begin before that approval.

Activation and deactivation orchestration, structured audit persistence, and
the remaining local API/persistence tests are now implemented. The Phase 5
implementation still requires independent audit approval before Phase 6.

The remediation adds generation-protected refresh, concurrent refresh
deduplication, revocation deletion, backend validation, and threshold-based
fresh-session checks. The invariant is: logout, revocation, or session
replacement permanently invalidates all refresh operations created under an
earlier session generation.

Verification: `pytest -q` should include the Phase 3 API tests and all prior
manifest, discovery, and storage tests.

## Outstanding Engineering Tasks

These are separate engineering-quality work items, not defects in the approved
Phase 4 implementation:

- Repository-wide lint cleanup.
- Repository-wide formatting.
- Static type cleanup.
- Dependency vulnerability audit.

The Phase 4 implementation has passed the Independent Audit. Ruff findings,
formatting normalization, existing mypy issues, and the dependency audit do not
block Phase 4 approval, but they must be completed before production readiness.

## Verification

`pytest -q` passes (9 tests at the time of this handoff).

## Security notes

The current implementation intentionally has no production API credentials,
license authority, update installer, or offline lease issuer. Those must be
server-backed and signature-verified before production use.
Operation-generation protection is implemented for Phase 5 activation/deactivation races. Independent audit should review the generation checks and deterministic concurrency tests; migrations and persistence-failure handling were intentionally left unchanged.
## Phase 5 Final Handoff

Phase 5 behavioral verification is complete: 79 tests pass. Open findings are covered by deterministic tests, including migration rollback/recovery, persistence failures, malformed responses, deactivation behavior, cache tampering/deletion, and concurrent SQLite writes. Independent audit may begin. Do not begin Phase 6 until approval.

## Phase 6 Handoff

The initial offline lease and authorization boundary is implemented in
`src/bke_licensing_agent/licensing/lease.py` and
`src/bke_licensing_agent/licensing/authorization.py`. It uses Ed25519 through
the established `cryptography` library, rejects unknown keys, and binds
authorization to validated product, installation, device, and version data.
The local environment could not download `cryptography` because PyPI DNS was
unavailable; cryptographic integration tests remain blocked until the
dependency is installed.

Phase 6.2 lease metadata persistence is complete and verified. Remaining Phase
6 work is online reconciliation, refresh, replay/generation ordering, and
concurrency; those are intentionally outside this increment.
