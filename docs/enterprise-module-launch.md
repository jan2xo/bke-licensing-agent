# Enterprise module launch boundary

The Agent may authorize an included module from a signed `bke.bundle-policy.v1` envelope. The policy binds source and target product IDs, versions, absolute executable paths, and SHA-256 digests. It is Ed25519 verified with the existing configured trust primitive; writable JSON or a hash sidecar is not authority.

On Windows, the request and redemption transport is a named pipe restricted to the current interactive user and LocalSystem. The Agent obtains the connecting PID from the kernel, opens that process, records its creation time and full image path, and hashes that image. Air Stack receives no bearer token. The Agent launches Render Dock through `LaunchExecutionService`, records the exact child PID/creation time/path/hash in memory, and permits one bounded redemption by that child. Missing, expired, replayed, wrong-process, wrong-installation, and wrong-device sessions fail closed.

The source licensing decision may be an existing valid offline signed-lease decision; module issuance and redemption add no network requirement.

This is a same-user, non-elevated desktop contract. It does not implement or certify Windows-service-to-desktop process launch, elevation crossings, cross-session launch, or Authenticode publisher verification. A future capability may add publisher/signature policy, handle inheritance, or protected-process constraints without accepting CLI flags, environment booleans, reusable tokens, or product-owned licensing rules.

## Wire contract

Products discover the per-user endpoint deterministically as `\\.\pipe\bke-licensing-agent-<first-16-hex-of-SHA256(current-user-SID)>-module-v1`. Messages are UTF-8 JSON prefixed by a four-byte unsigned big-endian length. The maximum JSON payload is 16 KiB and the default read deadline is five seconds.

`InstalledAgentRuntime` owns the optional `ModuleLaunchPipeServer` lifecycle alongside the existing loopback server. Production composition supplies only Agent-verified signed policy contexts and Agent-created authorization decisions to `EnterpriseModulePipeDispatcher`; products cannot register contexts or decisions through the wire.

Every request has `schema: "bke.module-ipc.v1"`, a non-empty `request_id` of at most 128 characters, and an `operation`:

- `launch` also has `policy_id`. No product ID, path, hash, flag, or caller-provided authorization decision is trusted; the Agent resolves the signed policy/context and authenticates the pipe peer.
- `redeem` has `installation_id` and `device_id`. The Agent authenticates the pipe peer and consumes the exact pending child session.

Responses echo `schema` and `request_id`. Success is `{ "ok": true, "result": ... }`; denial is `{ "ok": false, "error": "<stable reason>" }`. A launch result contains `child_pid` and `policy_id`. A redemption result contains `enterprise: true`, `policy_id`, and `expires_at`. Unknown schemas, operations, policies, malformed bindings, oversized messages, timeouts, replay, expiry, and identity mismatches fail closed. No secret or bearer authority appears in any message.
