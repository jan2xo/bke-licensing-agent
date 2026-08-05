# Architecture

This document describes the planned architecture for the BKE Licensing Agent.

## Goals

- Discover installed BKE applications using `bke.manifest.json`
- Validate manifests against a stable JSON schema
- Communicate with the BKE licensing platform over HTTPS
- Enforce licensing policy without embedded product-specific rules
- Support controlled offline operation through signed leases
# Phase 6 addition

Phase 6.5 extends the boundary with `LaunchAuthorizationService`; decision and
product execution remain separate responsibilities.

Validated Manifest -> verified signed Lease -> AuthorizationService -> typed
AuthorizationDecision. The authorization layer does not launch applications.
Phase 7 adds an execution boundary after authorization; it cannot authorize by
itself and never treats local persistence as a trust anchor.
Phase 8 recovery is downstream of trust boundaries and can only validate or
report local state; it cannot authorize execution.
Phase 9 adds an update-preparation boundary after platform trust verification;
it does not install or execute artifacts.
