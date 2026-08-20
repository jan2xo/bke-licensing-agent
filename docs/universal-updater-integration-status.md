# Universal updater integration status

The Agent now depends on bke-updater-core from the universal updater feature branch and exposes an Agent-owned UpdateOrchestrator boundary.

The orchestrator:

- validates trusted local manifest paths;
- verifies bke.update-policy.v1 with trusted Ed25519 public keys;
- rejects stale policy revisions;
- persists only verified policy envelopes;
- computes UP_TO_DATE, UPDATE_AVAILABLE, UPDATE_REQUIRED, or UNSUPPORTED;
- evaluates cached policies offline without weakening signature verification;
- persists transaction state through updater-core.

The existing UpdateService remains present for its existing signed metadata and resume tests. It is not replaced by a product-specific updater.

Runtime certification is still pending: the local Digital Solutions stack must be connected to the Agent client, then product replacement, health checks, self-update, rollback, and interruption recovery must be executed.
