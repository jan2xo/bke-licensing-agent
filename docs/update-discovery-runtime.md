# Installed update discovery runtime

The installed Licensing Agent refreshes update state independently from product authorization. It uses the active persisted signed lease envelope to call Digital Solutions over verified HTTPS, verifies `bke.update-policy.v1` with the installed trusted keyring, and atomically caches policy and secret-free status under the Agent data directory.

Refresh begins after runtime startup and repeats on an hours-scale cadence. Timeouts, malformed responses, invalid signatures, stale revisions, and Digital outages become `refresh_failed` or `verification_failed`; they never affect the signed offline lease authorization path.

Products may read only the loopback status surface and request a refresh or Agent-owned Update Center. Status never contains the lease, policy, artifact URL/hash, filesystem path, or helper arguments. Browser-origin requests and oversized/non-JSON mutations are rejected.

The current candidate intentionally stops before installer execution. Current Digital product artifacts are installer executables, while the proven Updater Core execution contracts accept a single replacement executable or a verified staged tree. A release-package/staging contract and Windows privilege/helper-authenticity certification are required before the Agent may safely execute those installers.
