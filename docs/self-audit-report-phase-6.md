# Phase 6 Self-Audit

The implementation fails closed for malformed envelopes, unknown keys,
unsupported algorithms, mismatched identity, product, device, and version, and
invalid time windows. The cryptographic dependency is declared but not
available in the current environment; Phase 6 is not ready for independent
approval until it is installed and integration-tested.
