# BKE Licensing Agent

**Current implementation:** .NET 10 Generation 2  
**Version:** 2.0.0 candidate  
**Windows architectures:** x64/AMD64 and ARM64  
**Production release:** pending signing/cutover

The BKE Licensing Agent is the shared, product-agnostic licensing, authorization, notification, update, and trusted-execution layer for BKE software.

The active repository tree is now **.NET 10-only**. The retired Generation 1 Python implementation remains available only through Git history and historical certification records.

## Active implementation

- `dotnet/src/BKE.LicensingAgent.Bootstrap/` — stable Windows service bootstrap
- `dotnet/src/BKE.LicensingAgent.Host/` — loopback runtime host
- `dotnet/src/BKE.LicensingAgent.Infrastructure/` — licensing/update/platform implementations
- `dotnet/src/BKE.LicensingAgent.Desktop/` — native Avalonia License Center
- `dotnet/src/BKE.LicensingAgent.Updater/` — elevated privileged update helper
- `dotnet/src/BKE.LicensingAgent.Provisioner/` — privileged machine trust provisioner
- `dotnet/tools/BKE.LicensingAgent.ReleaseTooling/` — release/trust/key tooling
- `packaging/windows/` — canonical x64 and ARM64 installers
- `certification/` — retained real-machine certification scripts/evidence documentation

## Windows machine contract

```text
BKE-Licensing-Agent
        ↓
service\bke-licensing-agent-service.exe
        ↓
runtime\bke-licensing-agent-runtime.exe
        ↓
127.0.0.1 / ::1 :43873
```

Supporting executables are also native .NET 10:

```text
license-center\bke-license-center.exe
updater\bke-updater-core.exe
provisioning\bke-privileged-provisioner.exe
```

## Build

Requires the .NET 10 SDK.

```powershell
dotnet build dotnet/src/BKE.LicensingAgent.Host/BKE.LicensingAgent.Host.csproj --configuration Release
dotnet build dotnet/src/BKE.LicensingAgent.Desktop/BKE.LicensingAgent.Desktop.csproj --configuration Release
```

Publish all native Windows support executables:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish_dotnet_windows_payloads.ps1 -Version 2.0.0 -Architecture all
```

The supported Windows release matrix is x64/AMD64 (Intel + AMD 64-bit) and ARM64.

## Certification state

Runtime bridge, canonical installer migration, signed self-update pre-publication, and broken-update rollback have all passed their certified phases. The .NET-only convergence is a new post-certification packaging/runtime wave and must pass its own hosted x64 and persistent ARM64 acceptance before production signing.

# BKE Licensing Agent Installation & Product Integration Standard

**Status:** Approved Architecture  
**Owner:** BKE Digital Solutions  
**Applies To:** All current and future BKE software products

---

# 1. Purpose

This document defines the official installation, packaging, update, and integration architecture for the **BKE Licensing Agent**.

The Licensing Agent is a reusable, product-agnostic component shared by every BKE application.

It must **not** be embedded as a separate licensing engine inside every software product.

Instead, every BKE installer installs or updates **one shared Licensing Agent**.

---

# 2. Core Principle

> Every BKE product uses one shared Licensing Agent.

The application identifies itself.

The Licensing Agent interprets the application's manifest and enforces the licensing protocol.

The Licensing Agent never contains product-specific business logic.

---

# 3. Architecture

```text
                    BKE Licensing Platform
                              │
                              │
                              ▼
                 Shared BKE Licensing Agent
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
      AIRSTACK           RENDERDOCK         Future Products
```

Every product communicates with the same installed Licensing Agent.

---

# 4. Installation Flow

## First Product Installation

```text
User launches AIRSTACK Setup
        │
        ▼
Verify installer package
        │
        ▼
Check if Licensing Agent exists
        │
        ├───────────────┐
        │               │
        ▼               ▼
Installed?           Not Installed
        │               │
        │               ▼
        │        Verify bundled agent
        │               │
        │               ▼
        │        Install Licensing Agent
        │               │
        │               ▼
        │        Register / Start Agent
        │
        ▼
Install AIRSTACK
        │
        ▼
Install bke.manifest.json
        │
        ▼
Agent discovers product
        │
        ▼
Activation / Lease Retrieval
        │
        ▼
Launch
```

---

## Additional Product Installation

Example:

RENDERDOCK

```text
Installer starts
        │
        ▼
Check Licensing Agent
        │
        ├──────────────┐
        │              │
        ▼              ▼
Compatible      Requires Upgrade
        │              │
        │              ▼
        │      Upgrade Agent
        │
        ▼
Install Product
        │
        ▼
Install Manifest
        │
        ▼
Agent discovers product
```

---

# 5. Shared Installation Layout

```text
C:\Program Files\BKE Digital Solutions\
│
├── Licensing Agent\
│      bke-agent.exe
│      version.json
│      config\
│      runtime\
│      trusted-keys\
│
├── AIRSTACK\
│      AIRSTACK.exe
│      bke.manifest.json
│
├── RENDERDOCK\
│      RENDERDOCK.exe
│      bke.manifest.json
│
└── Future Product\
       executable
       bke.manifest.json
```

Runtime data should live in a protected shared location.

Example:

```text
C:\ProgramData\BKE Digital Solutions\
        Licensing Agent\
```

Containing:

- SQLite database
- Audit logs
- State
- Runtime cache

---

# 6. Installer Responsibilities

Every BKE installer shall:

- Verify installer integrity
- Detect Licensing Agent
- Read installed version
- Compare against minimum required version
- Install when missing
- Upgrade when necessary
- Never silently downgrade
- Install product files
- Install validated manifest
- Register the product
- Confirm Licensing Agent availability
- Roll back safely on failure

---

# 7. Product Manifest

Every product supplies:

```text
bke.manifest.json
```

Example:

```json
{
  "productId": "airstack",
  "displayName": "AIRSTACK",
  "version": "1.0.0",
  "entryPoint": "AIRSTACK.exe",
  "minimumAgentVersion": "1.0.0",
  "artifacts": [
    {
      "path": "AIRSTACK.exe",
      "sha256": "<trusted hash>"
    }
  ]
}
```

The manifest identifies the application.

The manifest never authorizes execution.

---

# 8. Product Integration Contract

Products communicate only with the Licensing Agent.

```text
Product
      │
      ▼
Licensing Agent
      │
      ▼
Licensing Platform
```

The product never performs:

- lease verification
- replay protection
- activation logic
- device identity
- licensing decisions
- trusted key management

Those responsibilities belong exclusively to the Licensing Agent.

---

# 9. Agent Versioning

The Licensing Agent has its own version.

Example:

```text
Licensing Agent 1.0.0
```

Products specify:

```text
minimumAgentVersion
```

Installer policy:

- Missing → Install
- Older → Upgrade
- Compatible → Keep
- Newer → Never downgrade

---

# 10. Agent Update Policy

Future agent updates must:

- Verify signatures
- Preserve local identity
- Preserve audit history
- Preserve trusted keys
- Apply database migrations safely
- Roll back on failure

---

# 11. Uninstall Policy

The Licensing Agent is a shared component.

Removing one product must **not** remove the Licensing Agent if another BKE product still depends on it.

Example:

```text
Installed

AIRSTACK
RENDERDOCK

↓

Remove AIRSTACK

↓

Licensing Agent remains
```

Only when the final BKE product is removed should the installer offer to uninstall the shared Licensing Agent.

---

# 12. Security Requirements

The installer must:

- Verify packages
- Verify hashes
- Verify signatures
- Reject path traversal
- Reject symlink escape
- Never install duplicate agents
- Never trust manifest-only authorization
- Never expose private keys
- Never pass secrets through command-line arguments

The Licensing Platform remains the authority.

---

# 13. Failure Recovery

If Agent installation fails:

```text
Abort installation safely.
```

If Product installation fails:

```text
Rollback product.

Keep the shared agent intact.
```

If Agent already services another product:

```text
Never remove it during rollback.
```

---

# 14. Demo Product

Before integrating AIRSTACK or any production software, create a permanent certification application.

Recommended name:

```text
BKE Demo Product
```

Purpose:

- Validate end-to-end licensing
- Validate activation
- Validate offline leasing
- Validate secure launch
- Validate recovery
- Validate updates

The Demo Product contains no real business logic.

---

# 15. Manual Certification

Every release should be manually verified.

Scenarios:

- Valid activation
- Invalid signature
- Wrong device
- Wrong installation
- Expired lease
- Revoked lease
- Superseded lease
- Offline valid lease
- Offline expired lease
- Missing manifest
- Modified executable
- Hash mismatch
- Agent upgrade
- Agent reinstall
- Product reinstall
- Second product installation
- Shared uninstall behavior

---

# 16. Product Lifecycle

Future workflow:

```text
Develop Product
        │
        ▼
Package Installer
        │
        ▼
Installer checks Licensing Agent
        │
        ▼
Install or Upgrade Agent
        │
        ▼
Install Product
        │
        ▼
Install Manifest
        │
        ▼
Activation
        │
        ▼
Lease Retrieval
        │
        ▼
Secure Launch
```

---

# 17. Supported Products

The Licensing Agent shall support:

- AIRSTACK
- RENDERDOCK
- WeatherWatch
- JANLIONEL SCRAPER
- Future BKE Products

No product-specific modifications to the Licensing Agent should be required.

Integration should only require:

- Standard Manifest
- Trusted Artifact Metadata
- Installer Integration
- BKE Client SDK / Local IPC

---

# 18. Final Standard

The approved deployment architecture is:

```text
          BKE Product Installer
                    │
                    ├──────────────► Install Product
                    │
                    ├──────────────► Detect Licensing Agent
                    │
                    ├──────────────► Install / Upgrade Agent
                    │
                    ├──────────────► Install Manifest
                    │
                    └──────────────► Register Product
                                   │
                                   ▼
                      Shared BKE Licensing Agent
                                   │
                                   ▼
                     BKE Licensing Platform
```

**This shall be the standard installation and integration model for all BKE Digital Solutions software products unless superseded by a future architectural decision.**

## Digital Solutions signed-lease activation

The product remains separate from the Agent. The primary Digital Solutions
activation bridge is `POST /api/licenses/activate`: the Agent sends the license
key, stable installation identity, canonical device identity, and a unique
operation ID. The Agent verifies the returned Ed25519 lease with a statically
provisioned trusted public key, persists only the verified lease, updates the
single active binding for the product/installation/device context, and then
evaluates local authorization. Private signing keys remain exclusively on the
licensing platform; the Agent never discovers or trusts arbitrary network keys.
