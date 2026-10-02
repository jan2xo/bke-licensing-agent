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

Rules:
- no automatic `pull_request` certification
- no ordinary branch-push certification
- reusable contract proof receives an explicit exact `source_sha`
- concurrency is keyed by the declared source SHA where the retained module supports it

Legacy-only for now:
- `pr-guard.yml` — automatic PR trigger removed
- `dotnet-production-signing.yml` — privileged production action, not certification
- `dotnet-signed-self-update.yml` — historical cross-repo proof hard-pins an old Digital Solutions SHA; must be rebuilt with explicit immutable cross-repo input before reactivation
- `dotnet-desktop-ui.yml` — standalone historical manual proof not currently part of the retained certification graph

Historical workflows are preserved verbatim under `.github/legacy-workflows/2026-10-02/`.
