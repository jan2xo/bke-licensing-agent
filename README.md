# BKE Licensing Agent

=================================================

BKE Licensing Agent

Version: 1.0.0

Status:

Engineering Complete

Implementation:
✓ Complete

Verification:
✓ Complete

Documentation:
✓ Complete

Self Audit:
✓ Complete

Independent Audit:
Pending

SOL Truth Audit:
Pending

Demo Product Certification:
Pending

Production Release:
Pending

=================================================

A reusable, product-agnostic licensing and application management agent for BKE Digital Solutions.

This repository contains the foundation for discovering BKE applications through `bke.manifest.json`, validating manifests, communicating with the BKE licensing platform, and enforcing licensing and update workflows without hardcoded product-specific logic.

## What is included

- `src/bke_licensing_agent/`: core Python package
- `schemas/bke-manifest.schema.json`: manifest validation schema
- `tests/`: unit and integration test skeletons
- `docs/`: architecture, status, and implementation documentation
- `samples/bke-demo-product/`: product-agnostic reference product
- `certification/`: manual certification procedures
- The Demo Product now requests authorization through the typed Licensing Agent boundary before entering RUNNING state.

Phase 3 adds a typed HTTPS client foundation under
`src/bke_licensing_agent/api/`. Configure an `https://` base URL through
`ApiConfig`; HTTP is accepted only for explicitly enabled local/test use.
Authentication, entitlement enforcement, and production endpoint availability
remain out of scope for this phase.

Phase 4 adds authentication and secure session management through the OS
keyring. Authentication proves identity only; it does not activate licenses or
authorize application launch.

Phase 5 adds online device identity, entitlement lookup, activation, and
verification. The platform remains authoritative; local activation metadata
never authorizes launch.

## Getting started

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
```

Run the CLI:

```bash
python -m bke_licensing_agent scan --paths "."
```

## Project goals

This agent is designed to:

- discover installed BKE products from configured locations
- validate application manifests
- identify supported products and versions
- manage licensing state securely
- support controlled offline operation
- prepare for update and launch workflows




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
