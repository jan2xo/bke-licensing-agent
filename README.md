# BKE Licensing Agent

A reusable, product-agnostic licensing and application management agent for BKE Digital Solutions.

This repository contains the foundation for discovering BKE applications through `bke.manifest.json`, validating manifests, communicating with the BKE licensing platform, and enforcing licensing and update workflows without hardcoded product-specific logic.

## What is included

- `src/bke_licensing_agent/`: core Python package
- `schemas/bke-manifest.schema.json`: manifest validation schema
- `tests/`: unit and integration test skeletons
- `docs/`: architecture, status, and implementation documentation

Phase 3 adds a typed HTTPS client foundation under
`src/bke_licensing_agent/api/`. Configure an `https://` base URL through
`ApiConfig`; HTTP is accepted only for explicitly enabled local/test use.
Authentication, entitlement enforcement, and production endpoint availability
remain out of scope for this phase.

Phase 4 adds authentication and secure session management through the OS
keyring. Authentication proves identity only; it does not activate licenses or
authorize application launch.

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
