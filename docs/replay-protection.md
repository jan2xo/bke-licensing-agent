# Lease Replay Protection

Launch authorization rejects metadata generations or server revisions older
than the latest trusted local record.

Persisted lease generation and server revision metadata provide monotonic
ordering. A lease with an older generation is rejected and cannot replace a
newer cached record. SQLite metadata is never an authority.
Replay protection is retained across service reconstruction by consulting the
persisted latest lease generation and server revision.
Replay lifecycle proof covers refresh, reconciliation, revocation, supersedence,
and service reconstruction using persisted generation/revision state.
