# Universal Updater Parallel Workstream Ownership

This file records the temporary ownership map used for the certification run.

| Workstream | Repository/surface | Protected shared surfaces |
|---|---|---|
| A Core mechanics | bke-updater-core transaction, helper, paths, archive safety, core tests | policy models and transaction state changes require reconciliation |
| B Authority | bke-digital-solutions update-policy API, release resolution, grants, authority tests | no updater-core internals |
| C Agent orchestration | bke-licensing-agent orchestrator, cache/offline tests, Agent-facing API | no core transaction internals |
| D Fixtures | disposable product fixture directories and manifests | no production product code |
| E Self-update | Agent-target harness using generic helper | coordinates core changes through A |
| F Adversarial/review | separate adversarial tests and review report | no production-code edits |
| G Documentation | certification/status/operations documents | documents only verified behavior |

Shared contract changes are single-owner changes. All workstreams consume the frozen `bke.update-policy.v1`, Ed25519, identity, artifact, minimum-version, transaction, helper, health, manifest, self-update, and cache semantics.
