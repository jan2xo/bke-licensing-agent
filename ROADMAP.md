# Roadmap

## Current milestone: Phase 4, authentication and secure sessions

- Complete manifest schema, semantic-version, and path-safety validation.
- Scan configurable locations without executing discovered files.
- Persist non-sensitive discovery records in SQLite.
- Provide typed HTTPS platform operations with safe timeouts, retries, and errors.
- Manage authenticated sessions using OS-backed secure credential storage.

## Next

- Add structured discovery diagnostics and duplicate handling.
- Add real platform authentication and account/session management.
- Add license activation, device identity, and entitlement verification workflows.
- Add secure token storage and signed offline lease verification.
- Add launch authorization and update artifact verification.

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
