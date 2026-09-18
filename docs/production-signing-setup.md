# Production Signing Setup

Status: **OWNER-AUTHORIZED SIGNING PATH — PUBLICATION STILL LOCKED**

This document describes the credentials required by `.github/workflows/dotnet-production-signing.yml`.

The workflow is manual-only and requires the exact dispatch token:

```text
AUTHORIZE_PRODUCTION_SIGNING
```

It rebuilds the Windows x64 and ARM64 installers using production public trust, Authenticode-signs both, verifies the approved signer identity, recomputes final signed hashes, and emits a signed release manifest.

It does **not** publish a GitHub release, software-catalog asset, or Digital Solutions deployment.

## Required protected GitHub secrets

Configure these under the protected `production-signing` environment before dispatch.

### Windows Authenticode identity

```text
BKE_WINDOWS_CODESIGN_PFX_B64
BKE_WINDOWS_CODESIGN_PFX_PASSWORD
```

`BKE_WINDOWS_CODESIGN_PFX_B64` is the base64-encoded approved BKE code-signing PFX.

The workflow imports the certificate into the ephemeral runner certificate store with `Exportable=false`, verifies its exact approved subject and thumbprint, signs both installers, then verifies `Get-AuthenticodeSignature.Status == Valid`.

If the approved production code-signing identity is non-exportable/HSM-backed instead of PFX-based, replace only the signing adapter step; keep the same signer subject/thumbprint and post-sign verification contract.

### Production privileged-target public trust

```text
BKE_PRODUCTION_TARGET_KEY_PEM_B64
BKE_PRODUCTION_TARGET_POLICY_JSON_B64
```

These values are public verification material only.

No private target-policy signing key may be supplied to the Agent build.

### Production update-authority public key

```text
BKE_PRODUCTION_UPDATE_AUTHORITY_KEY_JSON_B64
```

Decoded JSON must match:

```json
{
  "schema": "bke.update-authority-key.v1",
  "key_id": "<production-key-id>",
  "algorithm": "Ed25519",
  "public_key": "<32-byte raw Ed25519 public key, base64>"
}
```

The corresponding private Ed25519 key belongs only in the protected Digital Solutions V2 authority boundary. It must never be committed, packaged in the Agent, or uploaded as a release artifact.

## Required workflow-dispatch inputs

```text
release_version
approved_signer_thumbprint
approved_signer_subject
production_update_key_id
authorization
```

Current release gate is locked to:

```text
release_version = 2.0.0
authorization = AUTHORIZE_PRODUCTION_SIGNING
```

The signer thumbprint and subject must exactly match the imported production certificate.

## Signed output contract

A successful run produces:

```text
BKE-Licensing-Agent-2.0.0-Windows-PRODUCTION-SIGNED-UNPUBLISHED
```

containing:

- signed x64 installer,
- signed ARM64 installer,
- `PRODUCTION-RELEASE-MANIFEST.json`.

Manifest schema:

```text
bke.production-release-manifest.v1
```

Required state:

```text
status              = SIGNED_VERIFIED
catalog_publication = NOT_AUTHORIZED
deployment          = NOT_AUTHORIZED
publish_allowed     = false
```

The final SHA-256 values are recomputed **after Authenticode signing**. Unsigned Phase 11 hashes are never reused as production release hashes.

## Production update-authority private key

The private Ed25519 update-authority key is consumed by BKE Digital Solutions V2, not by this repository.

Digital Solutions V2 expects the protected authority bundle that includes:

```text
BKE_AGENT_UPDATE_SIGNING_KEY_ID
BKE_AGENT_UPDATE_SIGNING_PRIVATE_KEY
BKE_AGENT_UPDATE_LATEST_VERSION
BKE_AGENT_UPDATE_MINIMUM_SUPPORTED_VERSION
BKE_AGENT_UPDATE_REVISION
BKE_AGENT_UPDATE_PUBLISHED_AT
BKE_AGENT_UPDATE_WINDOWS_X64_SHA256
BKE_AGENT_UPDATE_WINDOWS_X64_SIZE
BKE_AGENT_UPDATE_WINDOWS_ARM64_SHA256
BKE_AGENT_UPDATE_WINDOWS_ARM64_SIZE
```

The SHA-256 and byte-size fields must come from the signed production release manifest, not the unsigned preflight.

## Still prohibited after signing

Even a successful production-signing run does not authorize:

- merging the stacked PRs,
- creating the production tag/release,
- uploading to the software catalog,
- activating the V2 production update authority,
- deploying Digital Solutions,
- customer publication.

Those remain separate owner-controlled gates.


## Loading protected signing inputs with GitHub CLI

Do this only from an owner-controlled workstation after the approved production credentials exist.

Create/configure the protected environment in GitHub first and require owner approval for deployments to it.

The commands below send secret values through stdin; they do not print the secret values.

~~~powershell
$repo = "jan2xo/bke-licensing-agent"
$environment = "production-signing"

# Approved Windows code-signing PFX.
$pfxPath = "C:\SECURE\BKE-Code-Signing.pfx"
[Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath)) |
  gh secret set BKE_WINDOWS_CODESIGN_PFX_B64 --env $environment --repo $repo

# PFX password: read interactively, do not place it in shell history.
$secure = Read-Host "Code-signing PFX password" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
  [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) |
    gh secret set BKE_WINDOWS_CODESIGN_PFX_PASSWORD --env $environment --repo $repo
}
finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

# Production privileged-target public verification material.
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\SECURE\production-target-key.pem")) |
  gh secret set BKE_PRODUCTION_TARGET_KEY_PEM_B64 --env $environment --repo $repo

[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\SECURE\production-target-policy.json")) |
  gh secret set BKE_PRODUCTION_TARGET_POLICY_JSON_B64 --env $environment --repo $repo

# Production update-authority PUBLIC key JSON only.
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\SECURE\bke-agent-update-prod-v1.json")) |
  gh secret set BKE_PRODUCTION_UPDATE_AUTHORITY_KEY_JSON_B64 --env $environment --repo $repo
~~~

Never load BKE-UPDATE-AUTHORITY-PRIVATE.pem into the Licensing Agent repository or its signing environment.

That private Ed25519 key belongs only in the protected Digital Solutions V2 authority boundary.

## Generating the production update-authority identity offline

Run the checked-in generator from an owner-controlled workstation, but place the output **outside all Git repositories**:

~~~powershell
dotnet run --project .\dotnet\tools\BKE.LicensingAgent.ReleaseTooling\BKE.LicensingAgent.ReleaseTooling.csproj --configuration Release -- generate-production-update-key --key-id bke-agent-update-prod-v1 --output-dir C:\SECURE\BKE-Agent-Update-Authority-v1 --authorization AUTHORIZE_OFFLINE_PRODUCTION_KEY_GENERATION
~~~

Expected output files:

~~~text
C:\SECURE\BKE-Agent-Update-Authority-v1\
├── BKE-UPDATE-AUTHORITY-PRIVATE.pem
├── bke-agent-update-prod-v1.json
├── PUBLIC-KEY-SHA256.txt
└── README-PRIVATE-KEY.txt
~~~

The generator refuses to write the private key under any Git working tree and never prints the private key.

## Signing-provider note

The current workflow adapter consumes an approved PFX because that is provider-neutral and testable on a hosted Windows runner.

If the approved BKE code-signing identity is non-exportable, HSM-backed, or provided through a cloud signing service, **do not export or weaken that key**. Replace only the Windows signing adapter steps while preserving:

- exact approved signer identity,
- SHA-256 file digest,
- trusted RFC3161 timestamping,
- Get-AuthenticodeSignature.Status == Valid,
- final signed SHA-256 recomputation,
- the signed-but-unpublished boundary.
