# Lease Refresh Policy

Refresh is required when no metadata exists or the lease expires within the
configured threshold. Concurrent refresh callers share one operation. Results
are typed and verified through online reconciliation before metadata changes.
