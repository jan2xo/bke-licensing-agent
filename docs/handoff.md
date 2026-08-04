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
- Add API client and authentication support
- Add secure local token storage, audit logging, and signed offline leases

## Verification

`pytest -q` passes (9 tests at the time of this handoff).

## Security notes

The current implementation intentionally has no production API credentials,
license authority, update installer, or offline lease issuer. Those must be
server-backed and signature-verified before production use.
