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
