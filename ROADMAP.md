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
