# Agent runtime bridge status

This branch proves a language-independent BKE Licensing Agent machine boundary without changing production release authority.

## Stable machine contract

- Windows service: `BKE-Licensing-Agent`
- Stable SCM executable: `service\\bke-licensing-agent-service.exe`
- Replaceable runtime payload: `runtime\\bke-licensing-agent-runtime.exe`
- Durable machine state: `%ProgramData%\\BKE Digital Solutions\\Licensing Agent`
- Local API: `127.0.0.1:43873`

The bootstrap owns process supervision and Agent-release polling. The runtime owns licensing capabilities. A future runtime may be .NET, Python, Rust, or another implementation as long as it preserves the runtime contract.

## Certification-only boundary

`packaging/windows/bke-licensing-agent-runtime-bridge.iss` is not a production installer. It emits an admin-only `bridge-cert.enable` marker under Program Files so the bootstrap can start the migration-guarded Gen2 host in GitHub Actions while disabling external self-update polling during the proof.

The canonical production Windows installer remains unchanged.

## Required proof before cutover

1. Install the existing Python Windows service.
2. Preserve ProgramData state.
3. Replace only the service/runtime payload with the stable bootstrap and Gen2 runtime.
4. Preserve the same SCM service name and executable path.
5. Recover the local API on port 43873.
6. Preserve ProgramData through the language transition.
7. Recover the local API after a service stop/start cycle.
8. Run the full Gen2 differential suite against the frozen Python oracle.

A real reboot, production-signed release package, and production update-authority publication remain separate release gates.
