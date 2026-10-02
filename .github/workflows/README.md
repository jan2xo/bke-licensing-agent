# Active GitHub Actions

This directory contains only intentional certification workflows.

Entrypoint:
- `certify.yml` — explicit `/certify ...` or `workflow_dispatch`

Retained proof targets:
- contracts
- windows-x64
- installer
- rollback
- preflight
- utm-trust
- acquisition
- self-update (requires explicit exact Digital Solutions SHA)

Rules:
- no automatic `pull_request` certification
- no ordinary branch-push certification
- reusable contract proof receives an explicit exact `source_sha`
- concurrency is keyed by the declared source SHA where the retained module supports it

Legacy-only for now:
- `pr-guard.yml` — automatic PR trigger removed
- `dotnet-production-signing.yml` — privileged production action, not certification
- `dotnet-desktop-ui.yml` — standalone historical manual proof not currently part of the retained certification graph

Historical workflows are preserved verbatim under `.github/legacy-workflows/2026-10-02/`.
