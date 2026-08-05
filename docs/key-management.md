# Key Management

Trusted public keys are supplied by configuration and selected by key ID.
Unknown IDs and unsupported algorithms are rejected. Ed25519 verification is
delegated to the `cryptography` library; custom cryptography is not used.
Rotation requires adding a new pinned key and retaining old keys only for the
leases they are intended to verify.
