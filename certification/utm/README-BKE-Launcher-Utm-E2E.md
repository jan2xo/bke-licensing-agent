# BKE Launcher + Render Dock — UTM End-to-End Runbook

TEST ONLY. Do not treat disposable target trust or unsigned candidates as production release material.

## Owner gates before the VM test

Do not begin the true cloud-backed install path until all of these are deliberately available:

1. Digital Solutions stack is available at the Agent's HTTPS platform base:
   - PR #177 — account-first foundation
   - PR #179 — Agent device authorization
   - PR #180 — Agent software catalog
   - PR #181 — standalone provision authorization
2. Digital Solutions runtime has:
   - V3_AGENT_ACCOUNT_SESSION_ENABLED=true
   - AGENT_ACCOUNT_SESSION_PEPPER configured with a non-placeholder secret of at least 48 characters
   - AGENT_ACCOUNT_SESSION_ENCRYPTION_KEY configured with a non-placeholder secret of at least 48 characters
3. Catalog data projects Render Dock for the UTM machine:
   - product_id = bke-render-dock
   - Product active, published, not archived
   - launcherExecutionType = STANDALONE
   - active Stable/LTS ProductVersion 1.0.2
   - operatingSystem = windows
   - architecture = arm64 for Windows ARM64 UTM
   - test account owns an active current entitlement through its claimed Claim Code
4. GitHub Release v1.0.2 exists in jan2xo/BKE_RENDER_DOCK and contains the architecture-specific updater metadata + ZIP. For ARM64:
   - Render-Dock-1.0.2-Windows-arm64.update.json
   - Render-Dock-1.0.2-Windows-arm64.update.zip

The Render Dock workflow artifact alone is not sufficient for the real install flow. The Agent intentionally resolves a GitHub Release by exact tag.

## Candidate inputs

Use only exact-head CI artifacts from the open draft stacks:

- Licensing Agent PR #44 — Agent with account/catalog/install/Open capabilities and interactive user-session launch.
- Launcher PR #3 — self-contained Windows x64 + ARM64 Launcher with Install + Open UX.
- Render Dock PR #20 — architecture-aware x64 + ARM64 updater release candidate.
- Licensing Agent PR #43 — UTM-TEST-ONLY Render Dock target trust.

Verify artifact digests shown by GitHub before moving files into the VM.

## Phase A — clean-machine evidence

Before installing anything:

1. Take a UTM snapshot.
2. Confirm there is no pre-existing:
   - C:\Program Files\BKE Digital Solutions\Render Dock
3. Install the exact-head Licensing Agent ARM64 candidate.
4. Reboot if the installer/acceptance kit requires it.
5. Confirm the BKE-Licensing-Agent service is Running.
6. Extract this UTM test-trust bundle.
7. Open elevated PowerShell in the extracted bundle and run:

   powershell -ExecutionPolicy Bypass -File .\Install-RenderDock-UtmTargetTrust.ps1

8. Capture evidence:

   powershell -ExecutionPolicy Bypass -File .\Collect-BkeLauncher-UtmEvidence.ps1 -OutputDirectory .\evidence-before-login

Expected:
- Agent health reachable on 127.0.0.1:43873
- UTM test trust marker present
- Render Dock not installed

## Phase B — shared account-session proof

1. Extract the ARM64 Launcher candidate.
2. Start bke-launcher.exe.
3. Click Continue with BKE.
4. Complete browser approval.
5. Refresh account status.
6. Confirm Launcher shows AUTHENTICATED.
7. Open BKE License Center separately.
8. Confirm License Center sees the same Agent-owned account without a second login.

This proves:

Launcher -> same Agent machine session <- License Center

No Launcher cloud token should be visible or copied anywhere.

## Phase C — catalog proof

In Launcher, refresh My Software.

Render Dock must project as:

- execution type: Standalone
- entitled: true
- latest version: 1.0.2
- state: Installable
- Install button visible

If it instead shows Release unavailable, inspect the Digital Solutions ProductVersion platform/architecture row.

If it shows Not entitled, inspect Claim Code -> Entitlement -> account linkage.

Do not work around either failure in Launcher.

## Phase D — privileged first install

1. Click Install exactly once.
2. Launcher should immediately show Installing and suppress another install click.
3. Agent must:
   - authorize the current account/product/version through Digital Solutions
   - resolve exact GitHub Release v1.0.2
   - resolve ARM64 metadata + ZIP
   - verify metadata identity
   - verify artifact size + SHA-256
   - verify signed UTM target policy
   - sign bke.privileged-provision-request.v1
   - invoke bke-updater-core.exe --privileged-provision
4. Approve Windows elevation if presented by the privileged boundary.
5. Wait for Agent discovery to observe the installed product.
6. Refresh software in Launcher.

Expected filesystem:

C:\Program Files\BKE Digital Solutions\Render Dock\RENDER DOCK.exe

Expected Launcher state:

Installed
Open button visible

## Phase E — interactive Open proof

1. Click Open in Launcher.
2. Agent re-checks current account/catalog entitlement.
3. Agent resolves the discovered executable internally.
4. Windows service crosses into the active interactive user session using the active console user token.
5. Render Dock must appear visibly on the logged-in desktop.

Expected:
- no executable path returned to Launcher
- no Session-0 invisible launch
- no second Launcher-side path resolution
- Render Dock performs its normal Licensing Agent authorization after launch

If no interactive user is logged in, the expected failure is NO_ACTIVE_USER_SESSION.

## Phase F — evidence after install/open

Run:

powershell -ExecutionPolicy Bypass -File .\Collect-BkeLauncher-UtmEvidence.ps1 -OutputDirectory .\evidence-after-open

Keep:
- machine architecture
- Agent service identity/state
- Agent health
- account-session projection
- software catalog projection
- privileged config presence
- disposable target-trust marker
- Render Dock local existence + entry-point SHA-256
- evidence SHA256SUMS.txt

Do not copy account-session secret files or DPAPI material into evidence.

## Phase G — negative checks

At minimum:

1. Click Install again after installed state:
   - it must not create a second first-install transaction.
2. Sign out from Launcher:
   - License Center must observe the same machine session becoming signed out.
3. Attempt Open while not entitled/signed out:
   - Agent must deny before invoking the executable.
4. A LAUNCHER_PLUGIN product must never receive the standalone Agent Open path.

## Phase H — cleanup

After UTM certification:

powershell -ExecutionPolicy Bypass -File .\Remove-RenderDock-UtmTargetTrust.ps1

Confirm the uniquely named UTM test key/policy are gone.

Keep the VM snapshot/evidence only as certification evidence. Never promote the disposable UTM target key to production trust.
