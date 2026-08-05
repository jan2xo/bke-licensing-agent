# Launch Authorization

`LaunchAuthorizationService` makes a typed decision only; it never launches
or executes products. It requires validated manifest provenance, a verified
signed lease, current identity bindings, generation/revision state, and a
trusted timezone-aware clock. Audit failure fails closed.

`AuthorizationService` returns a typed decision and never launches a product.
Authorization requires a validated manifest and a verified lease matching the
installation, device, product, and version. Expired, future, mismatched, or
invalid state fails closed.
## Phase 6.5 remediation

Authorization uses a single-flight key over product, device, session generation,
installation generation, lease input, version, and online mode. Waiting callers
receive the completed typed decision, and the flight is removed on both success
and failure. Verification and final identity/session checks fail closed as
`stale_operation`; malformed algorithms and envelopes map to
`malformed_lease`. Audit persistence failure maps to `audit_failed`.
Lease replacement invalidates older authorization references through the
persisted generation and server-revision ordering check before success.
The final matrix proves authorization cannot survive refresh, reconciliation,
revocation, or supersedence replacement of the trusted lease state.
