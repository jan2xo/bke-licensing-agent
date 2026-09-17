# BKE Licensing Agent .NET 10 Generation 2

This directory contains the Generation 2 migration of the BKE Licensing Agent.

## Migration authority

Python at `feat/notification-feed-provider` commit `77bdcd0be364192a6c1adea073659c4a462ce0e7` is the frozen Generation 1 behavioral oracle for this migration wave. The shipping Python runtime is not replaced, deleted, or silently redirected by work in this directory.

The stale `refactor/dotnet10-agent-vnext` branch is archaeology only. Its useful composition-root and certification ideas are retained here because they were already present in the frozen Python baseline; the stale branch itself is not merged into Generation 2.

## Safety gate

The .NET host remains opt-in and refuses to start unless:

```text
BKE_AGENT_VNEXT_ENABLE=1
```

This is a development/certification guard, not a stable-channel switch.

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

## Current first-wave scope

The first Gen2 wave is deliberately narrow:

- freeze the exact Python behavioral baseline;
- inventory the current external/runtime contract in `contracts/gen1-baseline.json`;
- bring the C# contract model up to the current licensing, update, typed-notification, and notification-inbox route set;
- split the old monolithic runtime port into capability-oriented application ports;
- retain fail-closed unavailable providers for capabilities not yet migrated;
- explicitly enforce the known loopback request guardrails rather than relying silently on ASP.NET defaults;
- certify the C# contract against the machine-readable inventory;
- run Python-oracle compatibility checks beside the .NET certification.

This wave does **not** migrate licensing policy, SQLite reads/writes, broadcast synchronization, update execution, service IPC, packaging, or License Center UI.

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
