# Lease Replay Protection

Persisted lease generation and server revision metadata provide monotonic
ordering. A lease with an older generation is rejected and cannot replace a
newer cached record. SQLite metadata is never an authority.
