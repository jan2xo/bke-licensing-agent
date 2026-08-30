# BKE Licensing Agent — .NET 10 vNext

This directory is the Generation 2 Licensing Agent implementation.

The existing Python implementation remains the canonical shipping Generation 1 runtime until each capability has been migrated and independently certified. Do not move, delete, or silently replace the Python runtime during the migration.

## Architecture rule

Each module must declare:

- WHAT I NEED
- WHAT I DO
- WHAT I GIVE

The host is a composition root only. It may wire capabilities, lifecycle, and adapters. It must not absorb licensing, update, discovery, trust, persistence, or UI business logic.

## Current migration wave

This first wave freezes the existing product-facing loopback contract and introduces a .NET 10 host boundary without taking over production runtime behavior.

The compatibility target remains:

- loopback host: `127.0.0.1`
- default port: `43873`
- `POST /v1/authorize`
- `POST /v1/activate`
- `POST /v1/license-center/open`
- `POST /v1/updates/check`
- `POST /v1/update-center/open`
- legacy browser route: `GET /license-center`

The .NET host is intentionally guarded by `BKE_AGENT_VNEXT_ENABLE=1`. Until migrated providers exist, it fails closed. It must not be packaged as the production replacement yet.

## Module ownership

### BKE.LicensingAgent.Contracts

WHAT I NEED: nothing.

WHAT I DO: define the stable loopback wire contract and typed DTOs.

WHAT I GIVE: route identities, capability identities, typed request/response shapes.

### BKE.LicensingAgent.Application

WHAT I NEED: Contracts.

WHAT I DO: define the provider port implemented by Agent capabilities.

WHAT I GIVE: `ILicensingAgentRuntime`.

### BKE.LicensingAgent.Host

WHAT I NEED: Application + Contracts + concrete providers supplied by composition.

WHAT I DO: bind loopback HTTP, validate the guarded vNext startup, map stable routes to the runtime port.

WHAT I GIVE: the local Agent process boundary.

## Migration gate

A Python capability is replaced only after its .NET implementation passes:

1. module certification,
2. contract/differential compatibility against the Generation 1 behavior where required,
3. composition certification for declared consumers,
4. exact candidate CI.

Only then may packaging switch that capability or the whole host to .NET 10.
