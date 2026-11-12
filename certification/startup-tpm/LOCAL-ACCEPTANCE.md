# LOCAL / PHYSICAL WINDOWS TPM 2.0 — BKE startup machine-key acceptance runbook

**Status:** HANDOFF, NOT EXECUTED. Owner: human operator with an isolated physical TPM-equipped Windows 11 (or supported Windows Server) test machine. Agent source baseline: `d2d07437c70fbe0e938c61c3d6d96bb01dd54278`. Track results and blockers in [Agent issue #130](https://github.com/jan2xo/bke-licensing-agent/issues/130). Do not use this to certify commercial/production installation.

## Scope: what a local PASS actually means

The existing `BKE.LicensingAgent.StartupTpmHardwareCertification` project only tests a disposable **machine-store CNG ECDSA P-256 / ES256** key under Microsoft's Platform Crypto Provider. Its `create`, `verify`, and `cleanup` invocations are separate processes. It checks KSP/algorithm/nonexportability/machine scope, exact public-key continuity, ES256 signs and verifies, and negative altered-nonce/signature cases. **This does not prove** a physical TPM manufacturer, EK/AIK provenance, manufacturer-certified attestation, a reboot, installation of an Agent TPM startup signer, a DS-registered identity, signed product-release provenance, Launcher, or customer direct-EXE startup.

Existing startup Agent → DS → Agent policy proof is **DPAPI Ed25519** ([#134](https://github.com/jan2xo/bke-licensing-agent/pull/134), [run #43285849422](https://github.com/jan2xo/bke-licensing-agent/actions/runs/43285849422)). Existing ACCOUNT session TPM ES256 key is different from privileged **installed startup** identity and must not be reused or assumed enrolled. **Digital Solutions v1 startup endpoints reject ES256.**

## Prerequisites / explicit human attestations

1. A physically controlled, disposable Windows x64 machine with **ready TPM 2.0** and access to Microsoft Platform Crypto Provider. A virtual TPM can prove local *virtual* TPM operations but **not physical** custody; record the machine category. This test will deliberately fail closed on missing TPM. macOS, ordinary hosted GitHub Windows runners and generic UTM without an independently classified TPM do not certify physical TPM.
2. Windows updates applied, UEFI Secure Boot/TPM enabled as appropriate, no business/corporate/prod Agent installed on this test machine. Verify no customer secrets, production keys, real email/payment credentials, account identities or production databases are present. **Never clear/reset the TPM** or touch other CNG keys to make this test green.
3. Administrator-controlled Windows PowerShell 7, .NET SDK **10.x**, Git, permission to create/delete a disposable **machine** CNG key; isolated test operator. Record OS build, TPM manufacturer/version, whether physical or virtual, Secure Boot status, hostname **redacted** in public evidence, and human reviewer. Do not upload device identifiers, EK private data, secrets or raw private keys.
4. Pin the **exact current merged Agent main SHA** when performing the run; do not use an unreviewed PR checkout on a privileged machine. Preserve that SHA, GitHub Actions run link (if applicable), and hardware/operator review outcome. If main moves, choose and record a newly certified main; never assume this example SHA is current.

## Read-only preflight — PowerShell on the Windows test machine

```powershell
$ErrorActionPreference = 'Stop'
Get-Tpm | Format-List TpmPresent,TpmReady,ManufacturerIdTxt,ManufacturerVersion
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber
Confirm-SecureBootUEFI   # Record result; unsupported firmware must be explained, never silently assumed
dotnet --version          # Must be .NET 10
git --version
```

If TPM is absent/unready or reported as virtual when physical evidence is required: **STOP / BLOCKED**. The probe does not justify clearing the TPM or changing production OS security.

## Exact-source isolated local run — NO cloud, no production change

Use a fresh test clone and a known merged exact SHA. Never put private material inside the repository or publicly shared evidence.

```powershell
git clone https://github.com/jan2xo/bke-licensing-agent.git
Set-Location bke-licensing-agent
$sha = (git rev-parse origin/main).Trim()
git checkout --detach $sha
if ((git rev-parse HEAD).Trim() -ne $sha) { throw 'Source drift' }

$env:BKE_ENVIRONMENT = 'certification'
$env:BKE_TPM_HARDWARE_CERTIFICATION_ENABLED = '1'
$keyName = 'BKE-PREPRODUCTION-STARTUP-TPM-' + [Guid]::NewGuid().ToString('N').ToUpperInvariant()
$evidence = Join-Path $env:TEMP ('bke-startup-tpm-' + [Guid]::NewGuid().ToString('N') + '.json')
$project = 'dotnet/certification/BKE.LicensingAgent.StartupTpmHardwareCertification/BKE.LicensingAgent.StartupTpmHardwareCertification.csproj'

dotnet run --project $project --configuration Release -- selftest-software-deny
if ($LASTEXITCODE -ne 0) { throw 'SOFTWARE KSP rejection failed' }

# CREATE: unique disposable MACHINE Platform-KSP key; no DPAPI fallback.
dotnet run --project $project --configuration Release -- create $keyName $evidence $sha
if ($LASTEXITCODE -ne 0) { throw 'Local TPM CREATE failed; STOP, investigate' }

# VERIFY: independent process, same nonexportable key, fresh ES256 sign,
# wrong nonce and forged signature rejected.
dotnet run --project $project --configuration Release -- verify $keyName $evidence $sha
if ($LASTEXITCODE -ne 0) { throw 'Local TPM VERIFY failed; STOP, investigate' }

# Copy only reviewed public evidence to a restricted test report BEFORE cleanup.
# Do not put user/machine identifiers or private keys in GitHub or public artifacts.
dotnet run --project $project --configuration Release -- cleanup $keyName $evidence $sha
if ($LASTEXITCODE -ne 0) { throw 'Verified cleanup failed: human investigation required' }
```

**Failure handling:** if creation or verification fails, preserve failure logs, the exact unique `$keyName`, the SHA and test machine classification for a trusted operator. If the proof file is missing/corrupt, `cleanup` deliberately refuses to delete an unverified machine key; **do not run arbitrary `certutil -deletekey` commands, clear TPM or delete other keys**. Manually review the exact test key before recovery. This local proof is a disposable system change (new CNG test key), so run it **only on a specifically approved test machine**.

## Optional controlled GitHub Actions route

Use the manually dispatched [`.github/workflows/startup-tpm-hardware.yml`](../../.github/workflows/startup-tpm-hardware.yml), only after an administrator has:

- Provisioned an isolated, reviewed, **nonproduction** self-hosted Windows x64 runner labeled `bke-disposable-tpm2`; guaranteed dedicated/no tenant cross-use. Human approves the `bke-disposable-tpm-review` GitHub Environment; no production repo secrets or credentials are assigned to the runner.
- Verified that the workflow runs **only** from reviewed, merged `main` and pins the exact `github.sha`; the runner checks `Get-Tpm`, creates/verifies the disposable key, uploads only public test evidence, then deletes that key after verification.
- Confirmed execution identity has machine-key permissions, outbound access is limited, and the runner is destroyed/reimaged or unregistered after use. Avoid persistent privileged self-hosted runners exposed to untrusted PRs.

Dispatch explicitly in GitHub Actions UI → **PREPRODUCTION - Manual TPM Machine-Store Evidence** → **Run workflow** on `main`; review the job and SHA. **Do not auto-run** or dispatch on generic hosted Windows.

## Acceptance record (human-signed checkpoint)

```text
BKE TPM LOCAL ACCEPTANCE — PREPRODUCTION
Date/time (UTC):
Human operator / independent reviewer:
Machine hardware type: PHYSICAL TPM2 / VIRTUAL TPM / NO TPM
Windows version / build:
TPM present+ready / firmware details / Secure Boot:
Exact merged Agent SHA:
Local command or manual workflow run URL:
SOFTWARE KSP DENIED: PASS / FAIL
Microsoft Platform Crypto Provider MACHINE P-256 create: PASS / FAIL
CNG private export denied: PASS / FAIL
Second-process same public SPKI + ES256 sign: PASS / FAIL
Altered nonce and forged signature denied: PASS / FAIL
Cleanup same exact disposable key: PASS / FAIL
Reboot persistence: NOT TESTED (requires separate scheduled human proof)
EK/AIK manufacturer attestation: NOT TESTED
Physical device provenance independently checked: YES / NO
Installed privileged Agent startup: NOT TESTED
Digital Solutions ES256 enrollment/issuance: NOT TESTED
Render Dock direct-EXE / Launcher E2E: NOT TESTED
Production: LOCKED
Result: LOCAL CNG TPM PROBE PASS / BLOCKED (not hardware-root attestation)
Evidence link and reviewer signoff:
```

Keep issue #130 OPEN for remaining product and DS acceptance. A local TPM test **must not** be represented as remote hardware attestation or proof that DPAPI installed startup was migrated to TPM.

**PRODUCTION LOCKED:** no production deployment/keys, real customers, production database, payment/email, shipping installer, signing cutover, catalog activation, or force push.
