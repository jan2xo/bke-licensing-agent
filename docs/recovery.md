# Phase 8 Recovery

Recovery validates local lease metadata and process state as untrusted data. It
never creates authorization, extends a lease, recreates signatures, or bypasses
the platform. Corrupt state produces a typed fail-closed result; missing state
is recoverable and requires normal Phase 6 verification before authorization.

Startup recovery is deterministic: validate lease metadata, invoke the injected
process recovery boundary, and report typed actions. Audit and cache records are
diagnostic only.
