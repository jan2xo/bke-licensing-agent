# Lease Lifecycle

The platform issues a signed lease envelope. The agent validates the envelope,
checks the pinned key identifier and Ed25519 signature, parses the payload, and
then evaluates time, generation, product, installation, device, and version
constraints. Local lease metadata is diagnostic only and is not a trust anchor.

Phase 6.2 persists metadata through `LeaseMetadataRepository`. It stores lease,
product, installation, device, generation, status, issuer, timestamp, and key
identifier metadata only. Signed payloads, signatures, public/private keys,
tokens, and license secrets are excluded.
