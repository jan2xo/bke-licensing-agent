# Phase 6 Self-Audit

Authorization is decision-only and does not execute processes, resolve paths,
or modify product files. Only verified signed leases can produce an allowed
decision.

Refresh does not persist signed payloads or keys and delegates authenticity and
authority checks to the existing verifier and reconciliation service.

Reconciliation never treats SQLite metadata as authoritative and checks the
session, installation generation, signature, identity, version, and lease
generation before persistence.

Online reconciliation is limited to platform-authoritative metadata cache
reconciliation; refresh, replay policy, and launch authorization remain out of
scope for this increment.

The implementation fails closed for malformed envelopes, unknown keys,
unsupported algorithms, mismatched identity, product, device, and version, and
invalid time windows. The cryptographic dependency is declared but not
available in the current environment; Phase 6 is not ready for independent
approval until it is installed and integration-tested.

The dependency is now available and the direct Ed25519 integration tests pass.
Lease metadata persistence, replay/generation ordering, and concurrent online
lease reconciliation remain unimplemented and are not claimed complete.

The metadata repository is intentionally diagnostic-only. A valid-looking
SQLite row cannot establish signature authenticity or authorize launch.
## Phase 6.5 remediation self-audit

The authorization boundary now deduplicates identical concurrent decisions,
cleans up in-flight state on all paths, rejects stale identity/session state,
rejects stale lease generation/revision, and fails closed on malformed input or
audit persistence errors. Repository-wide Ruff, formatting, and mypy findings
remain engineering debt.
Final closure confirms stale lease replacement is rejected using persisted
generation/revision ordering and audit failures remain explicit fail-closed
partial results. No launch execution is performed.
Final proof matrix completed with 145 passing tests. Stale authorization is
rejected from persisted generation/revision and revoked/superseded metadata.
