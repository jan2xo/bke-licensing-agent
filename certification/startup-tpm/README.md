# BKE PREPRODUCTION hardware-only machine TPM acceptance probe

Tracking: [Agent #130](https://github.com/jan2xo/bke-licensing-agent/issues/130). This intent **does not** certify customer product startup, physical TPM provenance or remote attestation.

## Verified starting point
- Agent main pinned at `b6185f48e604aa48ac13916e2d2598089ffe89aa`; DPAPI Agent → Digital Solutions → Agent signed policy [#134](https://github.com/jan2xo/bke-licensing-agent/pull/134) exact-head [#43285849422](https://github.com/jan2xo/bke-licensing-agent/actions/runs/43285849422) PASS.
- DS main pinned `0be43d74d45b6a24307ddb626a6fd0d4b70bbba4`; its startup enrollment/issuance accepts **Ed25519 only**.
- Prior Agent Windows CI explicitly logged **TPM-specific hardware execution: NOT AVAILABLE ON HOSTED RUNNER — SOFTWARE FALLBACK CERTIFIED**.
- Existing user-session Agent ES256 TPM key store has a different binding and is **not** an installed machine-startup key. Never reuse, migrate, or represent it as the privileged installer signer.

## Single intent
Add **certification-only, fail-closed** proof tooling for native TPM 2.0 Windows **machine-store** ECDSA P-256 signing using Microsoft's Platform Crypto Provider. It must use a unique ephemeral CNG machine key, no software-provider/DPAPI fallback, no private export, two separate processes for creation and reopen, fresh tamper-resistant signature verification, provider/curve/export-policy/machine-scope checks, and cleanup of only the exact identified disposable test key. The probe is not a production Agent feature or a customer key lifecycle.

## Certification / ownership
- **Primary owner:** Agent preproduction native machine-trust hardware proof.
- **Required before merge:** `contracts windows-x64` at exact PR head: compile the probe, guard the manual workflow, run native Windows **software-KSP rejection** without creating any TPM key, and preserve existing native payload proof. The **existing** trusted-main `windows-x64` dispatcher invokes the exact candidate's `FirstInstallCertification → MachineKeyCertification`, which runs this negative probe. Do not rely on a new branch-only workflow step for premerge proof. This wave is certification-only; production runtime, installer and DS contracts remain untouched.
- **Not required:** `installer rollback acquisition utm-trust startup-handshake self-update fraction-lease preflight` because no installed runtime trust or packaging behavior changes.
- **Hardware acceptance:** A separate **manual main-only** self-hosted Windows/TPM run is required after the source probe is merged. `contracts` is NOT actual TPM evidence. Fail the hardware job if Windows TPM isn't present/ready, CNG Platform key cannot be created/reopened, nonexportability fails, or a signature is forged. No fallback to DPAPI. A trustworthy human must validate the hardware/runner context; hosted CI cannot supply it.
- **Cross-repo:** reuse fixed DS source only. No DS mutation, ES256 enrollment, algorithm downgrade or imported signing material.

## Acceptance classification
- Source + Windows software-KSP denial CI PASS = strict probe implemented and its **non-TPM rejection behavior** proven; still NOT hardware acceptance.
- Hardware CNG Platform machine key creation/open/sign/verify PASS on a separately approved real TPM runner = **local TPM-backed signing proof**, not manufacturer/EK/AIK remote attestation.
- Full installed machine proof → DS two-admin enrollment/ES256 v2 → signed DS policy → product direct EXE authorization = **separate cross-repo wave**, still BLOCKED.

**PRODUCTION LOCKED.** No deployment, production DB, keys, signing cutover, release, physical customer machine enrollment, installer publication, payment, email, or force push.
