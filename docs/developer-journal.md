# Developer Journal

Phase 6.5 added the decision-only launch authorization service with signed
lease, identity, generation/revision, clock, and audit fail-closed checks.

Phase 6.4 added threshold refresh decisions, persisted server revisions, and
single-flight refresh with older-generation rejection.

Phase 6.3 completed platform-authoritative online lease reconciliation with
typed results and deterministic stale-operation tests.

Phase 6.3 added online reconciliation with platform-authoritative replacement
and signed revocation/supersession invalidation.

## Initial session

- Created project scaffold
- Added CLI entrypoint
- Added manifest schema and validation
- Added basic unit tests for manifest parsing
# Development journal

## 2026-08-04

- Reviewed the product-agnostic licensing-agent brief and existing scaffold.
- Completed the Phase 0 documentation records and environment template.
- Hardened manifest entry-point and icon validation for POSIX and Windows path
  syntax, including traversal prevention.
- Made discovery-path parsing platform-aware and added explicit database close
  support/context management.
- Verification: `pytest -q` -> 9 passed.
- No licensing authority, credentials, update installer, or signature issuer
  was added; those remain server-backed follow-up work.

## Phase 3 — Licensing platform client

- Added typed API configuration, endpoint definitions, request/response models,
  and an injectable requests-based transport.
- Added HTTPS enforcement, connect/read timeouts, request IDs, bounded retries
  for idempotent requests, and explicit safe error mappings.
- Kept non-idempotent device and verification requests free of automatic retry.
- Added deterministic unit coverage for configuration, responses, status errors,
  retries, serialization, and redaction.

## Phase 4 — Authentication and secure sessions

- Added typed login, refresh, logout, session, token, and authentication-state
  models.
- Added authentication service and session manager over the Phase 3 API client.
- Added keyring-backed credential storage with safe failure and corruption
  handling; no token persistence was added to SQLite.
- Added serialized refresh coordination and immediate in-memory invalidation on
  logout or revoked validation.
- Verification: `pytest -q` -> 32 passed; `python3 -m compileall -q src tests`
  -> passed.

## Phase 4 remediation

- Added a generation counter and condition-variable refresh state machine.
- Deduplicated simultaneous refresh calls and rejected stale responses after
  logout, revocation, or session replacement.
- Added threshold-based `ensure_fresh_session()` behavior and removed the
  unused refresh-retry-limit configuration.
- Added backend validation and direct mocked-keyring tests for secure storage.
- Verification: `pytest -q` -> 41 passed.

## Phase 5 — Device identity and activation

- Added secure persistent installation identity and a versioned SHA-256 device
  fingerprint over normalized platform signals.
- Added typed licensing models, API contracts, activation service, and a
  non-sensitive SQLite activation-cache migration.
- Added fail-closed license-state mapping and preserved authenticated-session
  requirements.

## Phase 5 completion work

- Completed activation and deactivation orchestration under one shared lock.
- Added structured non-sensitive audit-event persistence for device,
  entitlement, activation, verification, and deactivation events.
- Added API contract, activation-cache, audit persistence, and orchestration
  tests. Verification: `pytest -q` -> 50 passed.

## Phase 4 independent audit follow-up

- The Phase 4 implementation passed the Independent Audit.
- Recorded engineering tooling debt instead of silently resolving it.
- Outstanding work includes repository-wide Ruff cleanup, formatting
  normalization and CI verification, existing mypy issues, and a dependency
  vulnerability audit in a network-enabled environment.
- Reported coverage remains 81%; future increases must be meaningful and focus
  on authentication, licensing, activation, offline licensing, updater, and
  launcher workflows.
- These items do not block Phase 4 approval but must be completed before
  production readiness.
Phase 5 remediation added operation generations for session, installation identity, and product/device ordering. Event-controlled tests prove stale activation and deactivation responses cannot restore or remove newer state.
Final Phase 5 verification completed against the current repository state. The authoritative result is 79 passed and 79 collected, with 85% coverage. All operation-generation, migration, persistence-boundary, malformed-response, cache-integrity, deactivation, and concurrent SQLite findings have mapped tests.
Phase 6 implementation added the signed lease model, Ed25519 verification
boundary, trusted key IDs, and offline authorization decisions. Cryptographic
integration verification is pending dependency installation because network
DNS was unavailable.
Phase 6 Security Remediation 001 upgraded cryptography from installed 45.0.7
to 50.0.0 under the `>=50,<51` policy. Ed25519 compatibility and the full
regression suite were reverified.

Phase 6.2 added a dedicated diagnostic-only lease metadata repository and
schema migration 3. SQLite rows remain untrusted and cannot authorize launch.
Phase 6.5 remediation added a keyed authorization single-flight boundary. The
owner performs verification once; waiters reuse the exact typed decision, and
flight cleanup is guaranteed. Final identity/session generation checks prevent
stale authorization after logout, replacement, or identity reset.
Final closure verification added direct audit transaction and replay lifecycle
tests. Authorization remains diagnostic-decision only and fail-closed.
The final proof matrix added separate deterministic lifecycle tests for refresh,
reconciliation, replay, revocation, supersedence, and stale replacement.
Phase 7 execution work added canonical manifest entry-point resolution, trusted
artifact hashing, final stale-state checks, and shell-free subprocess launch.
Phase 8 recovery validates local lease metadata and delegates process recovery
without granting authorization or recreating trust material.
