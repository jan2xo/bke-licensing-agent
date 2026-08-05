# Lease Refresh Policy

Authorization reads the latest reconciled generation/revision and rejects
stale lease state.

Refresh is required when no metadata exists or the lease expires within the
configured threshold. Concurrent refresh callers share one operation. Results
are typed and verified through online reconciliation before metadata changes.
Refresh replacement advances the persisted generation/revision ordering; older
authorization inputs are stale and cannot authorize.
Refresh replacement proof confirms older authorization references fail closed.
