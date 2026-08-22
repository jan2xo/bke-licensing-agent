# v1.0.0 packaging implementation

This change prepares implementation-green native packaging. It does not create
a release tag or publish binaries.

## Shared runtime contract

Each platform installs the Agent as an operating-system-managed background
runtime. The GUI License Center is installed separately and remains on-demand.
The Agent command is `serve`, binds only to `127.0.0.1:43873`, and stores
durable licensing/device state outside the application installation directory.

| Platform | OS manager | Application path | Durable state |
| --- | --- | --- | --- |
| macOS | LaunchDaemon | `/Library/Application Support/BKE Digital Solutions/Licensing Agent/` | `/Library/Application Support/BKE Digital Solutions/Licensing Agent Data/` |
| Windows x64 | Windows Service | `C:\Program Files\BKE Digital Solutions\Licensing Agent\` | `C:\ProgramData\BKE Digital Solutions\Licensing Agent\` |
| Linux amd64 | systemd | `/opt/bke-digital-solutions/licensing-agent/` | `/var/lib/bke-digital-solutions/licensing-agent/` |

## Candidate artifacts

- `BKE-Licensing-Agent-1.0.0-Windows-x64.exe`
- `BKE-Licensing-Agent-1.0.0.pkg`
- `bke-licensing-agent_1.0.0_amd64.deb`

The hosted workflow builds each candidate on its native GitHub runner and
uploads it as a workflow artifact. Native clean-install, reboot, upgrade,
authorization, and uninstall certification remains required before a GitHub
Release or `v1.0.0` tag is authorized.

Normal uninstall removes the service and application files but preserves the
durable state directory. A deliberate full purge is a separate operator action.

## Windows state boundary

The installer does not grant `users-modify` permission to the ProgramData
directory or its `trusted-keys` child. The Windows Service is registered using
the pywin32 default service account (LocalSystem); ordinary interactive users
access the Agent through its loopback API and do not receive direct write
access to trusted keys, device identity, or authoritative licensing state.

The hosted packaging workflow also records runtime dependency evidence from the
installed package dependency closure separately from build-tool inventory, runs
safe `--help` smoke checks against the frozen binaries, and binds evidence to
the exact pull-request head SHA used for checkout and manifest generation.
