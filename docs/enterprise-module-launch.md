# Enterprise module launch boundary

The Agent may authorize an included module from a signed `bke.bundle-policy.v1` envelope. The policy binds source and target product IDs, versions, relative manifest entry points, and SHA-256 digests. It is Ed25519 verified with the existing configured trust primitive; writable JSON or a hash sidecar is not authority.

The signed policy is intentionally installation-path independent. Absolute machine paths are rejected because a release-signed bundle policy must survive normal installation-root differences and upgrades. At runtime the Agent resolves each signed product/version/entry-point tuple through its own validated discovery state, then verifies the real executable path and hash before launch.

On Windows, the request and redemption transport is a named pipe restricted to the current interactive user and LocalSystem. The Agent obtains the connecting PID from the kernel, opens that process, records its creation time and full image path, and hashes that image. Air Stack receives no bearer token. The Agent launches Render Dock through `LaunchExecutionService`, records the exact child PID/creation time/path/hash in memory, and permits one bounded redemption by that child.

The source licensing decision is freshly re-evaluated for every launch request from the existing locally verified signed Air Stack lease. The Air Stack `installation_id` is supplied only to locate that signed local binding; it is not authority and cannot bypass the authenticated source process or signed bundle policy. Render Dock does not echo Air Stack installation/device values during redemption: the Agent-created exact child process identity is the rendezvous authority.

The source licensing decision may be an existing valid offline signed-lease decision; module issuance and redemption add no network requirement.

This is a same-user, non-elevated desktop contract. It does not implement or certify Windows-service-to-desktop process launch, elevation crossings, cross-session launch, or Authenticode publisher verification. A future capability may add publisher/signature policy, handle inheritance, or protected-process constraints without accepting CLI flags, environment booleans, reusable tokens, or product-owned licensing rules.

## Agent-owned policy composition

Signed bundle envelopes live in the Agent-owned `bundle-policies` directory under the configured Agent data directory. At installed runtime startup on Windows, the Agent verifies each envelope with configured trusted Ed25519 keys, resolves both products from Agent discovery state, requires the signed relative entry points to equal each validated manifest entry point, and constructs only those verified launch contexts. Invalid, unsigned, unknown-key, stale-version, mismatched-entry-point, or undiscovered policies are ignored and therefore cannot create a launch endpoint context.

The current v1 composition expects policy/discovery state to exist before the Agent runtime starts. If activation supplies trusted keys while the runtime is already serving, the Agent re-attempts module-server construction after successful activation. Air Stack packaging is responsible for installing the certified signed policy and both product artifacts, refreshing Agent discovery, and starting/restarting the same-user Agent runtime in the correct order.

## Wire contract

Products discover the per-user endpoint deterministically as `\\.\pipe\bke-licensing-agent-<first-16-hex-of-SHA256(current-user-SID)>-module-v1`. Messages are UTF-8 JSON prefixed by a four-byte unsigned big-endian length. The maximum JSON payload is 16 KiB and the default read deadline is five seconds.

`InstalledAgentRuntime` owns the `ModuleLaunchPipeServer` lifecycle alongside the existing loopback server when at least one valid signed bundle context is available. Products cannot register contexts, paths, hashes, product IDs, or authorization decisions through the wire.

Every request has `schema: "bke.module-ipc.v1"`, a non-empty `request_id` of at most 128 characters, and an `operation`:

- `launch` has `policy_id` and source Air Stack `installation_id`. The Agent resolves the signed policy, authenticates the pipe peer, freshly verifies the local signed Air Stack lease for that installation/device/version, verifies the target artifact, and launches it itself.
- `redeem` has no product, installation, device, token, or capability input. The Agent authenticates the connecting peer and atomically consumes the exact pending Agent-launched child session by PID, creation time, resolved executable path, and SHA-256.

Responses echo `schema` and `request_id`. Success is `{ "ok": true, "result": ... }`; denial is `{ "ok": false, "error": "<stable reason>" }`. A launch result contains `child_pid` and `policy_id`. A redemption result contains `enterprise: true`, `policy_id`, and `expires_at`. Unknown schemas, operations, policies, missing source installation binding, oversized messages, timeouts, replay, expiry, and identity mismatches fail closed. No secret or bearer authority appears in any message.

## Future / not implemented

Consumer Render Dock may later expose separately purchased capabilities or add-ons. That future entitlement model is intentionally not implemented by this bundle policy. Static Air Stack product composition remains a signed Agent-owned bundle policy; customer/device entitlement remains the signed Air Stack lease.
