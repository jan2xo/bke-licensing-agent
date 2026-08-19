# Local Agent integration sample

This test-only sample product is deliberately licensing-blind. It knows only
its product identity, version, installation identity, and the loopback Agent
URL. It never stores license keys, calls Digital Solutions, parses leases, or
handles signing keys.

The Agent API binds to `127.0.0.1` and exposes only `POST /v1/authorize`.
