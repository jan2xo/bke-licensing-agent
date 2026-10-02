param(
    [ValidateSet("x64")]
    [string]$Architecture = "x64",

    [string]$DigitalSolutionsSigningPublicKeyPath = "",

    [ValidatePattern("^$|^[A-Za-z0-9._-]{1,128}$")]
    [string]$DigitalSolutionsSigningKeyId = "",

    [ValidatePattern("^$|^[0-9a-fA-F]{64}$")]
    [string]$DigitalSolutionsSigningPublicKeySha256 = "",

    [switch]$ForceDigitalSolutionsSigningTrust
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this UTM TEST-ONLY trust installer from an elevated PowerShell."
}

$bundleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceRoot = Join-Path $bundleRoot $Architecture
$marker = Join-Path $sourceRoot "DISPOSABLE-TEST-ONLY.txt"
if (!(Test-Path $marker)) {
    throw "Disposable UTM trust marker is missing for architecture '$Architecture'."
}

$privateKeyMatch = Get-ChildItem -LiteralPath $sourceRoot -Recurse -File |
    Select-String -Pattern "BEGIN PRIVATE KEY" -SimpleMatch |
    Select-Object -First 1
if ($null -ne $privateKeyMatch) {
    throw "Refusing a disposable trust bundle that contains private-key material."
}

$dataRoot = Join-Path $env:ProgramData "BKE Digital Solutions\Licensing Agent"
$configPath = Join-Path $dataRoot "privileged-update.json"
if (!(Test-Path $configPath)) {
    throw "BKE Licensing Agent privileged configuration is unavailable. Install/certify the Agent first."
}

$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$keyDir = [IO.Path]::GetFullPath([string]$config.target_keys_dir)
$policyDir = [IO.Path]::GetFullPath([string]$config.target_policies_dir)
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $dataRoot "privileged"))

foreach ($path in @($keyDir, $policyDir)) {
    if (-not $path.StartsWith($expectedRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Agent target-trust path escaped the expected protected ProgramData root: $path"
    }
}

$keyName = "utm-render-dock-x64-target-v1.pem"
$policyName = "utm-render-dock-windows-x64-v1.json"

$sourceKey = Join-Path (Join-Path $sourceRoot "target-keys") $keyName
$sourcePolicy = Join-Path (Join-Path $sourceRoot "target-policies") $policyName
if (!(Test-Path $sourceKey) -or !(Test-Path $sourcePolicy)) {
    throw "Disposable Render Dock trust files are incomplete for '$Architecture'."
}

New-Item -ItemType Directory -Force $keyDir | Out-Null
New-Item -ItemType Directory -Force $policyDir | Out-Null

Copy-Item -LiteralPath $sourceKey -Destination (Join-Path $keyDir $keyName) -Force
Copy-Item -LiteralPath $sourcePolicy -Destination (Join-Path $policyDir $policyName) -Force

$installedMarker = Join-Path $dataRoot "UTM-TEST-ONLY-Render-Dock-target-trust.txt"
@"
UTM TEST ONLY
architecture=$Architecture
key=$keyName
policy=$policyName
installed_at=$([DateTimeOffset]::UtcNow.ToString("O"))
DO NOT USE THIS TARGET TRUST FOR PRODUCTION.
"@ | Set-Content -LiteralPath $installedMarker -Encoding utf8

Write-Host "UTM TEST-ONLY Render Dock target trust installed."
Write-Host "architecture=$Architecture"
Write-Host "key_sha256=$((Get-FileHash (Join-Path $keyDir $keyName) -Algorithm SHA256).Hash.ToLowerInvariant())"
Write-Host "policy_sha256=$((Get-FileHash (Join-Path $policyDir $policyName) -Algorithm SHA256).Hash.ToLowerInvariant())"


$hasDigitalSolutionsSigningTrustInput =
    -not [string]::IsNullOrWhiteSpace($DigitalSolutionsSigningPublicKeyPath) -or
    -not [string]::IsNullOrWhiteSpace($DigitalSolutionsSigningKeyId) -or
    -not [string]::IsNullOrWhiteSpace($DigitalSolutionsSigningPublicKeySha256)

if ($hasDigitalSolutionsSigningTrustInput) {
    if ([string]::IsNullOrWhiteSpace($DigitalSolutionsSigningPublicKeyPath) -or
        [string]::IsNullOrWhiteSpace($DigitalSolutionsSigningKeyId) -or
        [string]::IsNullOrWhiteSpace($DigitalSolutionsSigningPublicKeySha256)) {
        throw "Disposable Digital Solutions signing trust requires public-key path, key id, and SHA-256 together."
    }

    $envPath = Join-Path $dataRoot ".env"
    if (!(Test-Path -LiteralPath $envPath)) {
        throw "Agent UTM environment is unavailable. Prepare the disposable Agent environment first."
    }

    $safe = @{}
    foreach ($line in Get-Content -LiteralPath $envPath) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith("#")) {
            continue
        }
        $separator = $trimmed.IndexOf("=")
        if ($separator -le 0) {
            continue
        }
        $name = $trimmed.Substring(0, $separator).Trim()
        if ($name -in @("BKE_ENVIRONMENT", "BKE_PLATFORM_BASE_URL")) {
            $safe[$name] = $trimmed.Substring($separator + 1).Trim().Trim('"').Trim("'")
        }
    }

    if ([string]$safe["BKE_ENVIRONMENT"] -cne "utm") {
        throw "Disposable Digital Solutions signing trust may be installed only when BKE_ENVIRONMENT=utm."
    }

    $platformUri = $null
    if (-not $safe.ContainsKey("BKE_PLATFORM_BASE_URL") -or
        -not [Uri]::TryCreate([string]$safe["BKE_PLATFORM_BASE_URL"], [UriKind]::Absolute, [ref]$platformUri)) {
        throw "Agent UTM platform authority is invalid."
    }

    $platformHost = $platformUri.Host.TrimEnd(".")
    if ($platformHost -ieq "jl-bke.com" -or
        $platformHost.EndsWith(".jl-bke.com", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing disposable signing trust while the Agent points at production authority."
    }

    $sourceSigningKey = (Resolve-Path -LiteralPath $DigitalSolutionsSigningPublicKeyPath).Path
    $sourceSigningContent = [IO.File]::ReadAllText($sourceSigningKey)
    if ($sourceSigningContent.Contains("BEGIN PRIVATE KEY") -or
        $sourceSigningContent.Contains("BEGIN ED25519 PRIVATE KEY")) {
        throw "Refusing signing trust input that contains private-key material."
    }
    if (-not $sourceSigningContent.Contains("BEGIN PUBLIC KEY") -or
        -not $sourceSigningContent.Contains("END PUBLIC KEY")) {
        throw "Disposable signing trust input must be a PEM public key."
    }

    $actualSigningSha256 = (Get-FileHash -LiteralPath $sourceSigningKey -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSigningSha256 -cne $DigitalSolutionsSigningPublicKeySha256.ToLowerInvariant()) {
        throw "Disposable signing public-key SHA-256 does not match the pinned operator value."
    }

    $trustedKeysDir = [IO.Path]::GetFullPath((Join-Path $dataRoot "trusted-keys"))
    $agentDataRoot = [IO.Path]::GetFullPath($dataRoot)
    if (-not $trustedKeysDir.StartsWith(
            $agentDataRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Agent trusted-key path escaped the expected protected ProgramData root."
    }

    New-Item -ItemType Directory -Force -Path $trustedKeysDir | Out-Null
    $signingDestination = Join-Path $trustedKeysDir ($DigitalSolutionsSigningKeyId + ".pem")

    if ((Test-Path -LiteralPath $signingDestination) -and -not $ForceDigitalSolutionsSigningTrust) {
        $existingSigningSha256 = (Get-FileHash -LiteralPath $signingDestination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($existingSigningSha256 -cne $actualSigningSha256) {
            throw "A different trusted public key already exists for '$DigitalSolutionsSigningKeyId'. Use -ForceDigitalSolutionsSigningTrust only for an intentional disposable UTM replacement."
        }
    } else {
        Copy-Item -LiteralPath $sourceSigningKey -Destination $signingDestination -Force
    }

    $installedSigningSha256 = (Get-FileHash -LiteralPath $signingDestination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedSigningSha256 -cne $actualSigningSha256) {
        throw "Installed disposable signing public key failed SHA-256 verification."
    }

    $signingMarker = Join-Path $dataRoot "UTM-TEST-ONLY-Digital-Solutions-signing-trust.txt"
    @"
UTM TEST ONLY
key_id=$DigitalSolutionsSigningKeyId
key_sha256=$installedSigningSha256
platform_authority=$($platformUri.AbsoluteUri.TrimEnd('/'))
installed_at=$([DateTimeOffset]::UtcNow.ToString("O"))
DO NOT USE THIS SIGNING TRUST FOR PRODUCTION.
"@ | Set-Content -LiteralPath $signingMarker -Encoding utf8

    Write-Host "UTM TEST-ONLY Digital Solutions signing trust installed."
    Write-Host "key_id=$DigitalSolutionsSigningKeyId"
    Write-Host "key_sha256=$installedSigningSha256"
    Write-Host "production_authority_blocked=true"
}
