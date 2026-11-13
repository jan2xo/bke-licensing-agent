# Agent-owned one-shot Digital Solutions startup policy acquisition — PREPRODUCTION

Parent: [Agent process-bound direct startup acceptance #130](https://github.com/jan2xo/bke-licensing-agent/issues/130).
Upstream Digital Solutions: [PR #372 merged source `b282c8d1664efd6a59df9672a549b313343fa508`](https://github.com/jan2xo/bke-digital-solutions/commit/b282c8d1664efd6a59df9672a549b313343fa508).
Agent source PR: #141.

## What this implements

A **one-shot, elevated, installed Windows provisioner command** obtains the
actual binary and privileged signed target policy from its protected
installation, creates a fresh domain-separated Ed25519 installation attestation
under its **separate machine DPAPI key**, posts that signed envelope to
the **staging-only** Digital Solutions `POST /api/agent-sessions/startup-policy`
and verifies the response independently using the **installed, public-only
account-product issuer trust**. Only after successful signature plus exact
product/version/installation UUID/image path/image SHA256/target SID matching
does it write the DS signed envelope to the protected Program Files Agent
startup-policy trust folder.

The signed policy's `activation_mode` expresses *cloud SQL activation policy*,
not the actual installed account or commercial license credential. It does not
grant startup by itself: the SYSTEM Agent separately verifies the actual
connecting PID/image hash/SID, policy, actual credential and persists a grant
audit. The Host reads installed trust on startup; **this command never
restarts the service or claims a positive grant**.

### Explicit operator-controlled invocation

Only on a separately approved **isolated nonproduction Windows installation**
whose provisioner already resides in:
`%ProgramFiles%\BKE Digital Solutions\Licensing Agent\provisioning\`

Set the following environment for that **privileged process only**:

```text
BKE_ENVIRONMENT=certification
BKE_STANDALONE_STARTUP_ATTESTATION_ENABLED=1
BKE_STANDALONE_STARTUP_POLICY_ACQUISITION_ENABLED=1
BKE_PLATFORM_BASE_URL=https://<separately approved nonproduction DS origin>/
```

The provisioner entrypoint (already installed with the Agent) accepts:

```text
bke-privileged-provisioner.exe --startup-policy-acquire <product-slug> <version> <installation-uuid> <target-user-sid>
```

The slug/version/UUID/SID must be explicitly approved installer inputs. The
command **never accepts an image path, image SHA, DS public/private key,
entitlement or policy mode** from the operator. It independently verifies
the signed protected install-target manifest and hashes the installed binary.

The DS endpoint must separately be deployed and enabled on approved staging
using two default-OFF switches. Its SQL must already contain actual approved
public-only Agent machine enrollment and an independently controlled ACTIVE
account-product issuer keyset. The installed Agent issuer trust bundle must
match the active DS public signing key. **Do not use the manually replayed
Neon mock branch as a genuine issuer.**

## Fail-closed transport and installed authority

- No production, customer, or unapproved `jl-bke.com` origin; non-loopback
  HTTP denied, HTTPS required. Explicit nonproduction origin has no credentials,
  path, query or fragment.
- A **single** bounded request with fixed `bke.installed-startup-issuance.v1`
  protocol, no cookies, redirects, proxy, browser Google login or bearer.
- Strict 201 status, protocol header, content type and bounded JSON response.
  Reject unknown/duplicate fields, mismatched outer signing kid/mode/expiry,
  untrusted issuer, forged signatures, stale windows and any mismatched
  observed product/version/installation/image/SID.
- Never export raw machine private key, signed attestation or DS signed policy
  to stdout, logs, HTTP query or unprotected temp files.
- Protected installed directory root is checked for reparse points. Write
  only after verified signature/identity; use atomic create-new + Win32
  SYSTEM/Administrators-only ACL, no silent overwrite and no automatic Host
  restart. A second policy for the same product is denied to avoid ambiguous
  authority. Operator-controlled replacement is a separate intent.
- Failure is a generic denial; no in-band attempt to enable user access,
  fake credentials, or recover via unsigned product manifests.
- Historical DS signing issuer provenance inside the signed payload remains
  `09c16bc5c7e1d6ab3cb8df0ba569e6da05498f3f` by existing signed-policy
  contract. The **new endpoint transport source pin** is the separate
  `b282c8d1664efd6a59df9672a549b313343fa508`.

## Certification and remaining evidence

Agent contracts certification uses disposable Ed25519 DS-style signatures and
mocked bounded HTTP for positive/negative verifier and transport behavior.
Native Windows build/installer/rollback certify only the source and packaged
provisioner boundary, without customer machine or real deployed DS access.
No real production signing/DB/release activation or protected human Windows
acceptance is authorized.

Still required independently before calling Phase 2/3 complete: approved
deployed nonproduction DS with genuine issuer custody, two actual authenticated
ADMINs and real enrolled installed machine key, independently issued ACCOUNT
or LICENSE_KEY credential, real installed Windows x64 SYSTEM service + Render
Dock POSITIVE grant, audit/provenance and human approval of
`bke-disposable-startup-review` (not dispatched). Production remains LOCKED.

Declared Agent graph for this source wave: `contracts windows-x64 installer
rollback`. Other release/production/crossrepo workflows not required.
