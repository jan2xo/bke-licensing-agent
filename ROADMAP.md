# Roadmap

## Current milestone: Phase 1, manifest and discovery foundation

- Complete manifest schema, semantic-version, and path-safety validation.
- Scan configurable locations without executing discovered files.
- Persist non-sensitive discovery records in SQLite.

## Next

- Add structured discovery diagnostics and duplicate handling.
- Add typed HTTPS API client and mock licensing service.
- Add secure token storage and signed offline lease verification.
- Add launch authorization and update artifact verification.

The platform remains the authority for product existence, entitlement, device
authorization, releases, and policy. Product-specific rules do not belong in
this repository.
