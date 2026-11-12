# Process-bound standalone startup authority — SOURCE / PREPRODUCTION slice

**Canonical issue:** [#130](https://github.com/jan2xo/bke-licensing-agent/issues/130).  
**Base Agent main:** `bff7b9ee7f449089e672e7418d6335114c156c91`.  
**Immutable DS producer:** `083ef5b46765384e8a442c5700a0cfe746d0dc4f`.  
**Immutable Launcher consumer:** `b7dc17316574c746c570d33bc603e03b94ac5105`.  
**Commercial signed key route:** existing `IAuthorizationService` / `bke.licensing.v3`, unchanged.

## Intent

Introduce an **Agent-owned, fail-closed authorization decision boundary** for a standalone product calling during its own startup, with process identity observed by the **Windows kernel**, not described by product-controlled HTTP/JSON. This is a foundational slice of the larger cross-repository issue; no product is allowed to treat it as a completed direct-executable anti-bypass gate before actual installed trust, IPC composition and SDK/product integration exist.

The product sends **no product ID, PID, path, user SID, installation ID, credential, account/session assertion or signing key as authority**. The attestor observes the connected named-pipe process. A separately trusted installer-provenance registry, which is **NOT** implemented by this slice, must map the observed process to a product/version/installation and a **verified signed executable digest**. A separately trusted immutable-mode authority, likewise **NOT** implemented by this slice, must supply SQL-owned `ACCOUNT`, `LICENSE_KEY`, or explicit `EITHER`. Missing implementations deny.

The Agent decision orchestrator requires the following *cumulative* gates:

1. Windows-only, bounded and recently started OS-attested process; image path, SHA-256, Windows SID, PID/start-time continuity; no supplied PID/path is accepted from product.
2. A trusted registry result exactly matching the observed image path and SHA-256. **Program Files path or writable SQLite inventory alone is NOT signature provenance.** Callers must not compose the service with a registry that trusts mutable product manifests.
3. Independently trusted activation policy: `ACCOUNT`, `LICENSE_KEY`, or **explicit** `EITHER`; no missing-mode fallback.
4. `ACCOUNT`: matching live authenticated DS catalog entitlement, standalone execution type, correct installed version and verified fresh DS account-product `OPEN` JWS through the existing Agent gate; no commercial-key substitution.
5. `LICENSE_KEY`: existing `IAuthorizationService` verified signed commercial lease for the exact product, version, installation. **No Google/account session**. A live account entitlement cannot substitute.
6. `EITHER`: allow only when either path independently passes its complete proof; remote account failures do not weaken the commercial proof; no borrowed credentials.
7. Recheck exact peer process identity (PID + kernel start time + executable image/hash) *after* authorization, reject replay of an already granted process, and fail closed if mandatory Agent audit cannot be committed.
8. Production denies unconditionally; no production signer, keys, catalog activation, DS deployment or release.

No executable permissions can be granted by the new source alone: **Host does not expose an endpoint**, no trusted installed provenance/mode implementation is composed, SDK/Render Dock do not consume this contract yet, and the current Launcher-mediated `/v1/software/open` and signed commercial key routes remain unchanged.

## Minimum intentional certification graph — this slice

**Required:** Agent `contracts` for standalone process/mode/credential matrix and Host-source non-exposure checks; Agent `windows-x64` for native OS peer process identity pipe fixture and native Windows source compilation.  
**Not required:** Agent `installer rollback acquisition utm-trust fraction-lease preflight self-update`: no privileged Host endpoint, packaging, trust store, signer, JWS verifier, key storage or release path is changed.  
**Cross-repo:** reuse already-certified immutable DS, Agent/Launcher source and @bke/licensing v0.10.0. No downstream code/pin changes in this slice.  
**Full CI:** NO. Explicit exact-head `/certify contracts windows-x64` only once candidate is finalized.

## Intentionally incomplete / next required integration ownership

1. Agent: implement **signed provenance** registry and immutable activation-mode authority; wire a **named-pipe Host listener** with strict Windows ACL and process peer binding; audit storage and real denial on every executable startup.
2. Shared BKE Desktop Licensing SDK: consume typed startup decision only; never hold DS signing keys or implement raw Agent transport.
3. Render Dock: actually invoke the SDK startup gate for direct EXE and Launcher entry; treat existing Air Stack child session as a separate signed process-bound credential; explicitly reconcile the legacy unsigned grace HTTP policy with DS/Agent before changing its business semantics.
4. Run exact-head Agent Windows installed tests and product-specific Render Dock Windows direct-run acceptance. No claim of real installed/customer/production E2E until proven.

**Production remains LOCKED.** No force push, production mutation, deployment, signer provisioning, installer/release publication, or real PayMongo/Resend activity.
