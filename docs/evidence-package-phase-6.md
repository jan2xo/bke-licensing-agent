# Phase 6 Evidence Package

Evidence includes lease model validation, unknown-key rejection, malformed
envelope rejection, deterministic clock authorization, identity/product/device
binding, version rejection, and expiration/not-before decisions. Cryptographic
signature evidence is blocked by unavailable dependency installation.

Persistence evidence covers migration version 3, typed repository operations,
safe replacement/deletion, corruption failure, sensitive-field exclusion, and
SQLite failure injection.

Updated evidence: `cryptography 50.0.0` is installed; 15 Phase 6 tests pass,
including valid signatures, altered payloads, altered signatures, and signed
revocation/supersession rejection.
