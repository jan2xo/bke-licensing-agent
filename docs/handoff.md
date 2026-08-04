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
