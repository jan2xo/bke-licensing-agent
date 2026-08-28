# Linux in-place upgrade lifecycle

Status: **IMPLEMENTED / NOT LIVE-CERTIFIED**.

The Debian package now follows the same restart-safe lifecycle principle already proven on macOS:

1. stop the existing `bke-licensing-agent.service` before package payload replacement;
2. wait until the service is no longer active;
3. let `dpkg` replace the packaged runtime while `/var/lib/bke-digital-solutions/licensing-agent` remains outside destructive cleanup;
4. reload systemd after the new unit/payload is installed;
5. preserve the unit's enabled boot policy across upgrades;
6. restart the Agent;
7. wait until systemd reports the service active;
8. fail package configuration if the replacement Agent cannot become active.

Machine licensing/trust state remains under:

`/var/lib/bke-digital-solutions/licensing-agent`

and is intentionally retained across package upgrade/removal.

## Certification boundary

This lifecycle is structurally aligned with the macOS in-place-upgrade repair, but Linux has **not** completed a real-machine old-package -> new-package authorization-preservation test. Do not report Linux in-place upgrade as certified until that test is explicitly performed and recorded.

Current priority is Windows and macOS consumer certification. Linux live certification is parked.
