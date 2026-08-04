# Device fingerprint

Fingerprint schema `bke-device-v1` normalizes platform, operating-system
release, and architecture signals, sorts them, and hashes the canonical value
with SHA-256. Raw signals are not logged, persisted, or sent to the platform.
