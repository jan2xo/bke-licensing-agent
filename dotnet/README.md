# BKE Licensing Agent .NET 10 Generation 2

This directory contains the Generation 2 migration of the BKE Licensing Agent.

## Migration authority

Python at `feat/notification-feed-provider` commit `77bdcd0be364192a6c1adea073659c4a462ce0e7` is the frozen Generation 1 behavioral oracle for this migration wave. The shipping Python runtime is not replaced, deleted, or silently redirected by work in this directory.

The stale `refactor/dotnet10-agent-vnext` branch is archaeology only. Its useful composition-root and certification ideas are retained here because they were already present in the frozen Python baseline; the stale branch itself is not merged into Generation 2.

## Phase 8 candidate boundary

On `feat/production-installer-gen2`, the migration-only Gen2 startup guard has been removed so the canonical Windows installer candidate can run the certified runtime bridge directly.

This is **not** a production cutover. The branch and its stacked PR remain draft/unmerged. Production signing, catalog publication, release/tag creation, and deployment are separate authorization gates.

The canonical candidate keeps these stable machine boundaries:

```text
BKE-Licensing-Agent
        ↓
service\\bke-licensing-agent-service.exe
        ↓
runtime\\bke-licensing-agent-runtime.exe
        ↓
127.0.0.1 / ::1 :43873
```

The existing Python/PyInstaller License Center remains a separate UI boundary during Phase 8.

## Boundary rule

Every module must be describable as:

```text
WHAT I NEED
WHAT I DO
WHAT I GIVE
```

The Host is a composition root. It owns loopback transport, lifecycle, dependency composition, and translation between HTTP and capability ports. It does not own licensing policy, notification policy, SQLite policy, update policy, Digital Solutions business rules, or interactive UI policy.

## Generation 2 module direction

```text
BKE.LicensingAgent.Contracts      stable product-facing wire contracts
BKE.LicensingAgent.Application    capability ports consumed by the Host
BKE.LicensingAgent.Licensing      authorization/activation/lease policy (later wave)
BKE.LicensingAgent.Notifications  typed notifications/broadcast policy (later wave)
BKE.LicensingAgent.Updates        product + Agent update orchestration (later wave)
BKE.LicensingAgent.Storage        schema-8 compatible persistence (later wave)
BKE.LicensingAgent.Platform       outbound platform communication (later wave)
BKE.LicensingAgent.Execution      privileged/process operations (later wave)
BKE.LicensingAgent.LicenseCenter  interactive recovery presentation (later wave)
BKE.LicensingAgent.Host           loopback composition boundary
```

The capability projects are introduced only as their parity waves begin. Do not create fake wrappers that merely relocate Python behavior.

## Current migration scope

The Gen2 migration has progressed through runtime, compatibility, installed-machine, and reboot certification. Phase 8 now migrates the canonical Windows installer while preserving the certified machine contract.

Phase 8 includes:

- canonical Windows x64 Gen2 installer packaging;
- a separate native Windows ARM64 Gen2 installer;
- stable SCM bootstrap + replaceable Gen2 runtime packaging;
- preservation of ProgramData / schema-8 state;
- transactional service/runtime rollback and local API health checks;
- architecture-aware Agent self-update discovery;
- continued Python/PyInstaller License Center packaging;
- hosted Windows proof of Python production installer → canonical Gen2 in-place migration.

Phase 8 does **not** authorize production signing, catalog publication, release/tag creation, production deployment, License Center language migration, or the Phase 9 production-signed self-update boundary.

## Frozen persistence invariant

Generation 1 currently uses SQLite schema version `8`. The notification campaign delivery mode is intentionally **not** persisted as a `delivery_mode` column in the `notifications` table. `EVERY_LAUNCH` is live campaign policy layered over schema 8.

A language migration alone is not authorization to bump the database schema.

## Certification

Run:

```bash
bash dotnet/certify.sh
```

The certification must keep both sides visible during migration:

```text
PYTHON ORACLE ✅
.NET GEN2 ✅
```

Only a later explicitly approved cutover wave may replace the shipping runtime or packaging.
