# BKE Update Policy Contract v1

All three BKE repositories use the exact signed envelope bke.update-policy.v1.

Required fields:

- schema
- product_id
- current_version
- latest_version
- minimum_supported_version
- channel (stable or lts)
- platform
- architecture
- release_id
- artifact_id
- artifact_sha256
- artifact_size
- content_type
- published_at
- issued_at
- revision
- signing_key_id
- algorithm (Ed25519)
- signature

The signature covers canonical UTF-8 JSON of every field except signature, serialized with sorted keys and compact separators. Unknown keys, unknown signing keys, stale revisions, mismatched product/platform/architecture/channel, invalid hashes, and invalid signatures fail closed.

Update decisions are deterministic:

- installed == latest: UP_TO_DATE
- installed < latest and installed >= minimum: UPDATE_AVAILABLE
- installed < minimum: UPDATE_REQUIRED
- malformed versions or installed > latest: UNSUPPORTED

The cloud selects the release and artifact. The Agent and updater validate local paths and perform bounded local operations only. No private signing key, object-store credential, shell command, or arbitrary filesystem operation is sent to the Agent.
