# BKE Licensing Agent runtime replacement contract

## Purpose

The installed BKE Licensing Agent must survive implementation-language changes without requiring a customer to manually reinstall it.

The persistent contract is the machine identity, service identity, durable data, update authority, and installer invocation contract. The Agent executable implementation is replaceable.

## Stable Windows machine contract

These values are compatibility boundaries and must not change during a runtime-language migration unless a separately certified migration explicitly updates them:

- Product ID: `bke-licensing-agent`
- Windows service name: `BKE-Licensing-Agent`
- Default install root: `C:\Program Files\BKE Digital Solutions\Licensing Agent`
- Service payload directory: `service`
- Service entry point: `service\bke-licensing-agent-service.exe`
- Durable data root: `C:\ProgramData\BKE Digital Solutions\Licensing Agent`
- Local API bind: `127.0.0.1:43873`
- Update authority endpoint: `/api/licensing-agent/update`
- Catalog source marker: `bke-software-catalog`
- Windows update artifact: executable installer (`.exe`)
- Silent installer invocation: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`

The implementation behind `bke-licensing-agent-service.exe` may be Python, .NET, Rust, or another runtime. The Windows Service Control Manager and product clients must not need to know which implementation is installed.

## Update initiator contract

Every canonical Agent generation must contain an update initiator that can:

1. Query Digital Solutions for the next Agent release using the currently installed version, platform, and architecture.
2. Validate the Agent product identity, source marker, current-version echo, version ordering, and catalog URL.
3. Download only an approved BKE software-catalog Windows installer within the configured size bound.
4. Prompt the active user for optional updates and prevent indefinite deferral of required updates.
5. Launch the installer silently from the machine Agent service context.

The update initiator does **not** own binary replacement. It only transfers authority to the signed/release-controlled installer boundary.

## Installer replacement contract

The installer owns the implementation-language transition:

1. Stop the existing `BKE-Licensing-Agent` service and wait until the SCM-owned process has exited.
2. Replace the service payload under the stable install root.
3. Preserve the durable ProgramData directory.
4. Register or reconfigure the same Windows service name to the stable service entry-point path.
5. Start the replacement service and require it to reach `Running`.
6. Leave the existing installation recoverable if payload replacement or service startup fails.

Service control must be implementation-neutral. Installers must use Windows SCM operations rather than runtime-specific service-management command-line verbs.

## Cross-runtime migration rule

A language migration is release-eligible only after certification proves:

`legacy installed Agent -> update authority -> installer download -> silent installer -> service replacement -> new runtime -> local API healthy -> reboot -> local API healthy`

The certification must also prove that the same durable licensing database, trusted keys, device identity, notifications, and updater state remain usable after migration.

## Current bridge

The legacy Python Windows Service already runs `AgentSelfUpdateCoordinator` on a background polling loop. It therefore provides the migration trigger for existing customer PCs.

.NET Gen2 must implement the same update-initiator contract before it can become canonical. That ensures a customer can move from Python to .NET and later from .NET to another implementation without a manual reinstall.

## Authority rule

Changing the Agent implementation language does not authorize weaker trust. Release publication, installer signing, update authority, target-policy authority, artifact integrity checks, and production cutover remain separate release gates.
