# Changelog

- Added product-agnostic launch authorization decisions without product execution.

- Added threshold-based lease refresh and generation/revision replay rejection.

## 0.1.0

- Added versioned manifest schema and Pydantic model validation.
- Added configurable product discovery and safe relative entry-point checks.
- Added SQLite persistence for discovered applications.
- Added initial CLI scan and cached-list commands.

## Unreleased — Phase 3

- Added typed licensing-platform API client foundation.
- Added validated API configuration, HTTPS enforcement, timeouts, request IDs,
  bounded idempotent retries, safe error mapping, and API contract tests.

## Unreleased — Phase 4

- Added authentication service and secure session manager.
- Added typed login, refresh, logout, and validation models and client methods.
- Added OS keyring credential storage with safe failure and deletion behavior.

## Maintenance

- Recorded repository tooling debt after the independent security audit.
- Deferred repository-wide linting, formatting, static typing, and dependency
  audit to a future engineering-quality milestone.

## Unreleased — Phase 5

- Added persistent installation identity and versioned privacy-conscious device
  fingerprints.
- Added typed entitlement, device registration, activation, and verification
  contracts with non-sensitive SQLite activation metadata.
## Phase 6

- Added platform-authoritative online lease reconciliation.

- Added signed offline lease and launch-authorization boundaries.
- Added trusted-key and deterministic clock validation.
## Security remediation

- Upgraded the Phase 6 cryptography policy from vulnerable 45.0.7-era releases
  to `cryptography>=50,<51`, which covers all fixes reported by pip-audit.
### Phase 6.5 remediation

- Added deterministic authorization single-flight and stale-operation rejection.
- Added malformed-input and concurrent success/failure coverage.
Phase 6 final closure records replay lifecycle, stale replacement, and direct
SQLite audit transaction evidence.
Final Phase 6 proof matrix completed for stale authorization and replay lifecycle.
Phase 7 adds a product-agnostic execution boundary with path and SHA-256
integrity checks, generation rechecks, and shell-free process launch.
Phase 8 adds deterministic startup recovery for untrusted lease and process state.
Phase 9 adds signed update metadata and staged artifact verification.
Phase 10 adds typed production configuration, startup validation, health, and rotating logs.
Added the BKE Demo Product reference sample and certification documentation.
Demo Product now requests typed Licensing Agent authorization before running.
