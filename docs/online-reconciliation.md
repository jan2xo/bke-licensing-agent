# Online Lease Reconciliation

`LeaseReconciliationService` treats the platform as authoritative. It verifies
the downloaded signed lease before comparing or replacing local metadata. A
newer valid generation replaces an older one; an older result is rejected.
Revoked and superseded responses delete local metadata. Session, identity, and
operation-generation changes invalidate in-flight results.

The service returns typed unchanged, updated, revoked, superseded, expired,
deleted, invalid, and failed states. Older generations cannot replace newer
metadata.
Reconciliation replacement or revocation is authoritative; authorization of an
older lease fails closed after the persisted latest-state check.
Reconciliation proof confirms revoked and replaced lease state invalidates older
authorization attempts before an allowed result is returned.
