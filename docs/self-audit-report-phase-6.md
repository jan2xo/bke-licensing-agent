# Phase 6 Self-Audit

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
