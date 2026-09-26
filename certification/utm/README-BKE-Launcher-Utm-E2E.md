# BKE + Render Dock — Disposable UTM End-to-End Runbook

TEST ONLY / PREPRODUCTION ONLY.

This run proves the current customer-facing architecture as one system:

```text
BKE Launcher
  -> BKE Licensing Agent (loopback + machine trust)
  -> disposable Digital Solutions (identity / catalog / entitlement / notifications)
  -> GitHub stable product release
```

It must not use the production Digital Solutions deployment, production database,
live PayMongo, Resend, production signing keys, production storage credentials, or
any `jl-bke.com` authority.

## Exact input boundary

Before the VM test, record all of these:

- exact merged Digital Solutions source SHA;
- exact BKE Launcher source SHA that produced the parent installer;
- exact Licensing Agent source SHA;
- SHA-256 of the BKE parent installer;
- exact Render Dock release tag and artifact hashes.

Use the BKE **parent installer** as the customer-facing installation unit. Do not
manually install a standalone Licensing Agent and then extract a separate Launcher
candidate for this certification.

The parent installer is PREPRODUCTION and must bundle the intended Agent source SHA.

## Phase 0 — disposable Digital Solutions authority

Use the current merged Digital Solutions source in the disposable Linux/Ubuntu UTM
host.

The canonical disposable authority is:

```text
https://bke-v3.test:8443
```

The disposable profile must remain isolated:

```text
PAYMENT_PROVIDER=mock
PAYMONGO_SECRET_KEY=
PAYMONGO_WEBHOOK_SECRET=
PAYMONGO_LIVEMODE=false
EMAIL_PROVIDER=log
RESEND_API_KEY=
CLAIM_CODE_CHECKOUT_ENABLED=false
AGENT_ACCOUNT_SESSION_ENABLED=true
```

Generation-prefixed capability names such as
`V3_AGENT_ACCOUNT_SESSION_ENABLED` and `V3_CLAIM_CODE_CHECKOUT_ENABLED`
are invalid.

Bring up and verify the authority:

```bash
git status --short
git rev-parse HEAD
./bke.sh disposable-up
./bke.sh disposable-doctor
```

Required final marker:

```text
DISPOSABLE CERTIFICATION GATE: PASS
```

Also verify the generated disposable environment without printing secrets:

```bash
grep -E '^(BKE_DISPOSABLE_CERTIFICATION|APP_URL|PAYMENT_PROVIDER|PAYMONGO_LIVEMODE|EMAIL_PROVIDER|CLAIM_CODE_CHECKOUT_ENABLED|AGENT_ACCOUNT_SESSION_ENABLED)=' .env.certification
if grep -Eq '^V[0-9]+_(CLAIM_CODE_CHECKOUT_ENABLED|AGENT_ACCOUNT_SESSION_ENABLED)=' .env.certification; then
  echo "version-prefixed environment variable detected"
  exit 1
fi
```

Determine the disposable host LAN IP:

```bash
hostname -I
```

Windows must reach that host on TCP 8443.

## Phase A — Windows disposable trust boundary

Use a disposable Windows UTM snapshot.

1. Map `bke-v3.test` to the current disposable Linux/Ubuntu LAN IP in the Windows
   hosts file.
2. Copy only the disposable CA certificate
   `.bke-disposable/tls/bke-v3-disposable-ca.crt.pem` to Windows.
3. From elevated PowerShell, import it into the test machine root store:

   ```powershell
   certutil -addstore -f Root .\bke-v3-disposable-ca.crt.pem
   ```

4. Verify LAN and TLS:

   ```powershell
   Test-NetConnection <disposable-host-lan-ip> -Port 8443
   Invoke-RestMethod https://bke-v3.test:8443/api/health/ready
   ```

Do not import the disposable CA on a production machine.

## Phase B — configure the Agent before BKE installation

Extract the exact UTM trust bundle produced for the intended Agent source SHA.

Before installing BKE, write the Agent's disposable authority file from elevated
PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\Prepare-BkeAgent-UtmEnvironment.ps1 `
  -PlatformBaseUrl "https://bke-v3.test:8443"
```

If this disposable VM already contains an older UTM Agent `.env`, replace it only
deliberately:

```powershell
powershell -ExecutionPolicy Bypass -File .\Prepare-BkeAgent-UtmEnvironment.ps1 `
  -PlatformBaseUrl "https://bke-v3.test:8443" `
  -Force
```

Safe values must be:

```text
BKE_ENVIRONMENT=utm
BKE_PLATFORM_BASE_URL=https://bke-v3.test:8443
```

The helper must reject `jl-bke.com` and every `*.jl-bke.com` authority.

## Phase C — install BKE as the root product

Use the architecture-correct PREPRODUCTION parent installer. On Windows ARM64:

```powershell
$installer = Resolve-Path .\BKE-*-PREPRODUCTION-Windows-arm64.exe
$installerHash = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant()
$installerHash
Start-Process -FilePath $installer -Verb RunAs -Wait
```

Expected:

```text
C:\Program Files\BKE Digital Solutions\BKE\bke-launcher.exe
BKE-Licensing-Agent service = Running
Agent loopback = 127.0.0.1:43873
```

BKE installation must install and own the Licensing Agent dependency. The user must
not need a separate Agent download.

After the parent install creates the privileged Agent configuration, install the
disposable Render Dock target trust:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-RenderDock-UtmTargetTrust.ps1 -Architecture arm64
```

Capture pre-login evidence with the exact stack provenance:

```powershell
powershell -ExecutionPolicy Bypass -File .\Collect-BkeLauncher-UtmEvidence.ps1 `
  -OutputDirectory .\evidence-before-login `
  -DigitalSolutionsSourceSha "<digital-solutions-sha>" `
  -LauncherSourceSha "<launcher-source-sha>" `
  -AgentSourceSha "<agent-source-sha>" `
  -ParentInstallerSha256 "$installerHash"
```

Expected before login:

- BKE executable exists;
- Agent service is Running under the installed service identity;
- Agent loopback is healthy;
- Agent environment is `utm`;
- Agent authority host is `bke-v3.test`;
- production authority is false;
- disposable target-trust marker exists;
- account session is not authenticated yet;
- Render Dock is not installed.

## Phase D — create/verify a disposable CUSTOMER account

Native BKE login accepts CUSTOMER credentials only. Do not use a production account
and do not use an ADMIN identity as a substitute.

Use the disposable Digital Solutions web surface to create a TEST customer account.
Because the disposable provider is `EMAIL_PROVIDER=log`, any verification message
stays in disposable application logs instead of being sent through Resend.

After account creation, verify the email inside the disposable environment and make
sure exactly one usable customer account is owned/selected for the first native-login
proof.

## Phase E — native BKE login and shared Agent session

Start:

```text
C:\Program Files\BKE Digital Solutions\BKE\bke-launcher.exe
```

In BKE:

1. enter the disposable CUSTOMER email;
2. enter the disposable password;
3. click **Sign in with BKE**;
4. if account selection is offered, select the intended disposable account;
5. confirm the Launcher reports `AUTHENTICATED`.

There is no browser/device-code approval in this path.

Open BKE License Center separately and confirm it sees the same Agent-owned account
without another login.

This proves:

```text
BKE Launcher -> same Agent-owned machine session <- License Center
```

Launcher must never receive the Agent refresh token or cloud session secrets.

## Phase F — Notifications authority proof

In BKE, open **Notifications** and refresh.

Verify:

- the inbox is account-scoped;
- ADMINISTRATORS-only messages do not appear in the Launcher account inbox;
- **Mark read** sends the receipt mutation through the Agent to Digital Solutions;
- the Launcher refreshes the authoritative inbox after success;
- **Dismiss** removes the dismissed notification only after the server-authoritative
  mutation and refresh;
- no optimistic local receipt state is required.

Capture evidence again after the notification proof. The evidence bundle includes the
Agent-projected account feed but no account-session secret material.

## Phase G — catalog / entitlement gate

Refresh **My Software**.

Render Dock must eventually project as:

```text
product_id: bke-render-dock
execution type: STANDALONE
latest version: 1.0.2
entitled: true
state: Installable
```

Required Digital Solutions catalog state:

- product active, published, not archived;
- `launcherExecutionType = STANDALONE`;
- stable/LTS ProductVersion `1.0.2`;
- operating system compatible with Windows;
- architecture `universal` is preferred for one release containing both x64 and
  ARM64 assets;
- active current entitlement for the selected disposable account.

Do not create duplicate `ProductVersion 1.0.2` rows for architectures.
`ProductVersion` is unique by product + version.

If `1.0.2` is published with incompatible metadata, unpublish it first, edit
compatibility through the owner surface, then republish through the normal release
gates. Do not bypass `RELEASE_COMPATIBILITY_EDIT_REQUIRES_UNPUBLISH`.

## Phase H — GitHub release gate

The stable GitHub release `v1.0.2` in `jan2xo/BKE_RENDER_DOCK` must contain the
architecture-specific updater metadata and ZIP. For ARM64:

```text
Render-Dock-1.0.2-Windows-arm64.update.json
Render-Dock-1.0.2-Windows-arm64.update.zip
```

The Agent resolves the exact GitHub Release tag. A workflow artifact alone is not a
substitute for the stable product release.

## Phase I — privileged first install

In BKE, click **Install** once.

Expected Agent path:

1. verify current account entitlement and requested product/version with Digital
   Solutions;
2. resolve exact GitHub release `v1.0.2`;
3. resolve ARM64 metadata + ZIP;
4. verify release metadata identity;
5. verify artifact size + SHA-256;
6. verify disposable signed target policy;
7. sign the privileged provision request;
8. invoke the verified privileged helper;
9. discover the installed product.

Expected filesystem:

```text
C:\Program Files\BKE Digital Solutions\Render Dock\RENDER DOCK.exe
```

Expected BKE state:

```text
Installed
Open button visible
```

A normal service-hosted Agent path must not require a second Launcher-side UAC
elevation.

## Phase J — interactive Open proof

Click **Open** in BKE.

Expected:

- Agent re-checks account/catalog entitlement;
- Agent resolves the discovered executable internally;
- the service crosses into the active interactive Windows user session;
- Render Dock appears visibly on the logged-in desktop;
- Launcher receives no executable path;
- Render Dock performs its own normal Agent authorization after launch.

If no interactive Windows user is logged in, the expected denial is
`NO_ACTIVE_USER_SESSION`.

## Phase K — lifecycle proof

After first install:

1. **Repair** — restore/reinstall the currently installed authorized version.
2. **Update** — only if a strictly newer authorized version exists. Do not use Repair
   as Update.
3. **Remove** — remove the Agent-managed Render Dock installation.
4. reinstall Render Dock if needed for reboot/recovery proof.
5. reboot Windows.
6. confirm BKE launches, the Agent service recovers, the account session/catalog
   recover according to their durable contracts, and Render Dock discovery remains
   correct.

Do not widen managed lifecycle behavior to `PRODUCT_INSTALLER` or
`LEGACY_UNKNOWN`.

## Phase L — negative checks

At minimum:

1. second Install after an Installed state must not create a duplicate first-install
   transaction;
2. sign out from BKE and verify License Center observes the same machine session
   becoming signed out;
3. Open while signed out/not entitled must be denied before process invocation;
4. a `LAUNCHER_PLUGIN` product must never receive the standalone Agent Open path;
5. replacing the Agent authority with `jl-bke.com` or any `*.jl-bke.com` host in
   `BKE_ENVIRONMENT=utm` must fail closed.

## Phase M — final evidence

With the intended final installed state, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Collect-BkeLauncher-UtmEvidence.ps1 `
  -OutputDirectory .\evidence-final `
  -DigitalSolutionsSourceSha "<digital-solutions-sha>" `
  -LauncherSourceSha "<launcher-source-sha>" `
  -AgentSourceSha "<agent-source-sha>" `
  -ParentInstallerSha256 "$installerHash"
```

Keep:

- `00-stack-provenance.json`;
- machine architecture/OS;
- Agent service identity/state;
- loopback health;
- selected account-session projection;
- software catalog projection;
- privileged configuration projection;
- disposable target-trust marker;
- safe Agent environment projection;
- Render Dock local existence + entry-point SHA-256;
- BKE Launcher existence + SHA-256/version;
- Agent-projected notification inbox;
- `SHA256SUMS.txt`.

Do not copy Agent account-session secret files, DPAPI material, production secrets, or
private signing keys into evidence.

## Phase N — cleanup

Remove only the disposable Render Dock target trust:

```powershell
powershell -ExecutionPolicy Bypass -File .\Remove-RenderDock-UtmTargetTrust.ps1
```

Confirm the uniquely named UTM key/policy and marker are gone.

The VM snapshot and evidence remain PREPRODUCTION certification material. Never
promote the disposable CA, disposable target trust, or disposable service authority
to production.
