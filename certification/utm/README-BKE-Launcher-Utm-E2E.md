# BKE Launcher + Render Dock — UTM End-to-End Runbook

TEST ONLY. Do not treat disposable target trust or unsigned candidates as production release material.

This certification must not use the production Digital Solutions deployment, production database, live PayMongo credentials, production webhooks, or production signing/encryption secrets.

## Owner gates before the VM test

Do not begin the true cloud-backed install path until all of these are deliberately available:

1. A disposable Digital Solutions V3 instance is running at a non-production authority.
   - It uses the same merged V3 application code.
   - It has its own disposable PostgreSQL data.
   - It uses PayMongo test credentials only.
   - PAYMONGO_LIVEMODE=false.
   - It does not use production webhook, signing, encryption, email, storage, or backup credentials.
   - Its hostname must not be jl-bke.com or any *.jl-bke.com host.
2. The disposable Digital Solutions runtime has:
   - V3_AGENT_ACCOUNT_SESSION_ENABLED=true
   - AGENT_ACCOUNT_SESSION_PEPPER configured with a non-placeholder secret of at least 48 characters
   - AGENT_ACCOUNT_SESSION_ENCRYPTION_KEY configured with a non-placeholder secret of at least 48 characters
3. Catalog data projects Render Dock for the UTM machine:
   - product_id = bke-render-dock
   - Product active, published, not archived
   - launcherExecutionType = STANDALONE
   - active Stable/LTS ProductVersion 1.0.2
   - operatingSystem = windows (or universal/any compatibility metadata)
   - architecture = universal is preferred when one release tag contains both x64 + ARM64 assets; exact machine architecture is also accepted
   - test account owns an active current Entitlement; acquisition may be direct commerce settlement or Claim Code redemption
4. If Digital Solutions already contains Render Dock ProductVersion `1.0.2` as x64-only, do not create a duplicate version row. `ProductVersion` is unique by product + version. Use the owner release UI:
   - Unpublish `1.0.2` in Release Center.
   - In Products, change compatibility to `Windows + universal`.
   - Save compatibility.
   - Return to Release Center and republish after the normal release gates are satisfied.
   - Published releases intentionally reject in-place compatibility widening with `RELEASE_COMPATIBILITY_EDIT_REQUIRES_UNPUBLISH`.
5. GitHub Release v1.0.2 exists in jan2xo/BKE_RENDER_DOCK and contains the architecture-specific updater metadata + ZIP. For ARM64:
   - Render-Dock-1.0.2-Windows-arm64.update.json
   - Render-Dock-1.0.2-Windows-arm64.update.zip

The Render Dock workflow artifact alone is not sufficient for the real install flow. The Agent intentionally resolves a GitHub Release by exact tag. Do not use the older x64-only `v1.0.2-utm-test` prerelease as an ARM64 substitute.

## Candidate inputs

Use only artifacts produced from the current merged Agent and Launcher main lines plus
the stable Render Dock v1.0.2 release. Verify artifact digests shown by GitHub before
moving files into the VM.

The UTM trust bundle contains:
- Prepare-BkeAgent-UtmEnvironment.ps1
- Install-RenderDock-UtmTargetTrust.ps1
- Remove-RenderDock-UtmTargetTrust.ps1
- Collect-BkeLauncher-UtmEvidence.ps1
- architecture-specific disposable Render Dock target trust

## Phase 0 — disposable Digital Solutions

Bring up the disposable Digital Solutions V3 instance first.

Its canonical runtime file remains exactly:

```text
.env
```

Use disposable/test values only. At minimum:
- V3_AGENT_ACCOUNT_SESSION_ENABLED=true
- unique UTM AGENT_ACCOUNT_SESSION_PEPPER
- unique UTM AGENT_ACCOUNT_SESSION_ENCRYPTION_KEY
- disposable database credentials
- PayMongo test secret/webhook credentials
- PAYMONGO_LIVEMODE=false
- test/disposable signing and encryption material
- non-production email/storage/backup configuration

Do not copy the VPS production .env into UTM.

Record the disposable Digital Solutions base URL. This is the only cloud authority the
UTM Agent may use.

## Phase A — clean-machine evidence

Before installing anything:

1. Take a UTM snapshot.
2. Confirm there is no pre-existing:
   - C:\Program Files\BKE Digital Solutions\Render Dock
3. Extract the UTM test-trust bundle before installing the Agent.
4. Open elevated PowerShell in the extracted bundle and write the Agent UTM environment:

   powershell -ExecutionPolicy Bypass -File .\Prepare-BkeAgent-UtmEnvironment.ps1 -PlatformBaseUrl "https://<disposable-digital-solutions>"

   If and only if Digital Solutions is intentionally on the same machine loopback over HTTP:

   powershell -ExecutionPolicy Bypass -File .\Prepare-BkeAgent-UtmEnvironment.ps1 -PlatformBaseUrl "http://127.0.0.1:<port>" -AllowInsecureLoopback

5. Inspect only the non-secret Agent environment fields:

   Get-Content "$env:ProgramData\BKE Digital Solutions\Licensing Agent\.env"

   Required:
   - BKE_ENVIRONMENT=utm
   - BKE_PLATFORM_BASE_URL points only to the disposable instance
   - no jl-bke.com authority
6. Install the current Licensing Agent ARM64 candidate.
7. Reboot if the installer/acceptance kit requires it.
8. Confirm the BKE-Licensing-Agent service is Running.
9. Install disposable Render Dock target trust:

   powershell -ExecutionPolicy Bypass -File .\Install-RenderDock-UtmTargetTrust.ps1

10. Capture evidence:

   powershell -ExecutionPolicy Bypass -File .\Collect-BkeLauncher-UtmEvidence.ps1 -OutputDirectory .\evidence-before-login

Expected:
- Agent health reachable on 127.0.0.1:43873
- Agent started with BKE_ENVIRONMENT=utm
- Agent authority is the disposable Digital Solutions instance
- production jl-bke.com authority is rejected by configuration
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

If it instead shows Release unavailable, inspect the Digital Solutions ProductVersion platform/architecture compatibility metadata. ProductVersion is unique by product + version, so a cross-architecture v1.0.2 should normally use architecture=universal rather than duplicate x64/ARM64 rows.

If it shows Not entitled, inspect the active Entitlement for the account and confirm its resourceId resolves to the Render Dock Product or one of its Editions. Claim Code is one acquisition path, not a catalog ownership requirement.

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
4. In the canonical installed Agent, the runtime is service-hosted under LocalSystem and the verified helper inherits that service privilege. A second UAC prompt is therefore not expected for the normal service path. A non-service/manual Agent may still use `runas`.
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
