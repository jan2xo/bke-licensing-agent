# Roadmap

Phase 6.5 final launch authorization decision layer is implemented; Phase 7
must not begin until independent audit approval.

Phase 6.4 refresh and replay ordering are implemented; final launch
authorization remains the next scoped increment.

## Current milestone: Phase 6, offline license lease and launch authorization

- Complete manifest schema, semantic-version, and path-safety validation.
- Scan configurable locations without executing discovered files.
- Persist non-sensitive discovery records in SQLite.
- Provide typed HTTPS platform operations with safe timeouts, retries, and errors.
- Manage authenticated sessions using OS-backed secure credential storage.
- Identify installations, register devices, retrieve entitlements, and activate
  eligible licenses online.

## Next

- Complete online lease reconciliation verification and later Phase 6 refresh/replay increments.

- Add structured discovery diagnostics and duplicate handling.
- Add real platform authentication and account/session management.
- Add license activation, device identity, and entitlement verification workflows.
- Add secure token storage and signed offline lease verification.
- Add launch authorization and update artifact verification.

Phase 6 adds signed offline lease verification and authorization decisions. The
agent never becomes the licensing authority and does not launch products.

The platform remains the authority for product existence, entitlement, device
authorization, releases, and policy. Product-specific rules do not belong in
this repository.

## Engineering Tooling Debt

### Code Quality

- Resolve existing repository-wide Ruff findings.
- Apply repository formatting consistently.
- Configure formatting verification in CI.

### Static Analysis

- Resolve the existing mypy typing errors.
- Add or improve missing type annotations.
- Add missing third-party type stubs where appropriate.

### Dependency Security

- Execute a dependency vulnerability audit (`pip-audit` or equivalent) in a
  network-enabled environment.
- Record discovered vulnerabilities and remediation actions.
- Repeat before production release.

### Test Coverage

- Current reported coverage: 81%.
- Future goal: increase meaningful coverage while prioritizing authentication,
  licensing, activation, offline licensing, updater, and launcher workflows.
- Do not increase coverage with trivial tests.

These are separate engineering-quality backlog items and do not block Phase 4
approval. They must be completed before production readiness.
Phase 6.5 remediation completed the authorization single-flight and stale-input
guards. Phase 7 remains gated on independent audit approval.
Phase 6 final closure evidence is complete; Phase 7 remains gated on audit.
Phase 6 final proof matrix is complete; Phase 7 remains independently gated.
Phase 7 secure product execution implementation started; independent audit and
the complete deterministic acceptance matrix remain required before Phase 8.
Phase 8 recovery service implemented as a fail-closed validation boundary.
Phase 9 secure update preparation implemented; installer execution is out of scope.
Phase 10 production hardening foundation implemented.
