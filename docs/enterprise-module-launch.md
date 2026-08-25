# Enterprise module launch boundary

The Agent may authorize an included module from a signed `bke.bundle-policy.v1` envelope. The policy binds source and target product IDs, versions, absolute executable paths, and SHA-256 digests. It is Ed25519 verified with the existing configured trust primitive; writable JSON or a hash sidecar is not authority.

On Windows, the request and redemption transport is a named pipe restricted to the current interactive user and LocalSystem. The Agent obtains the connecting PID from the kernel, opens that process, records its creation time and full image path, and hashes that image. Air Stack receives no bearer token. The Agent launches Render Dock through `LaunchExecutionService`, records the exact child PID/creation time/path/hash in memory, and permits one bounded redemption by that child. Missing, expired, replayed, wrong-process, wrong-installation, and wrong-device sessions fail closed.

The source licensing decision may be an existing valid offline signed-lease decision; module issuance and redemption add no network requirement.

This is a same-user, non-elevated desktop contract. It does not implement or certify Windows-service-to-desktop process launch, elevation crossings, cross-session launch, or Authenticode publisher verification. A future capability may add publisher/signature policy, handle inheritance, or protected-process constraints without accepting CLI flags, environment booleans, reusable tokens, or product-owned licensing rules.
