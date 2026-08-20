# Universal updater integration status

The Agent owns orchestration while bke-updater-core owns product-neutral artifact verification, staging, replacement, health checking, rollback, and durable transaction state. Digital Solutions remains the update authority.

The verified boundary is:

- Digital Solutions resolves disposable persisted release, artifact, and entitlement data.
- POST /api/agent/updates/check returns signed bke.update-policy.v1.
- The bounded DownloadGrant HTTP endpoint redeems the artifact once.
- The Agent verifies the Ed25519 policy and artifact size/SHA-256.
- updater-core installs the executable, performs health verification, and records COMMITTED or ROLLED_BACK.

The Agent also persists self-update transactions and uses the external helper boundary; it does not replace its running process in place.

CI evidence:

- Agent CI authority runtime PASS: 32362565359.
- Cross-repository authority and executable certification PASS: 32362299204 and 32362565363.
- Digital Solutions CI PASS: 32362674227.
- Updater-core CI PASS: 32361339728.

These results use disposable PostgreSQL, Redis, MinIO, artifacts, licenses, and Ed25519 keys only. Production/VPS resources and production signing material are not part of this certification.
