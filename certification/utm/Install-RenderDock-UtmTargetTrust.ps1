param(
    [ValidateSet("auto","x64","arm64")]
    [string]$Architecture = "auto"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this UTM TEST-ONLY trust installer from an elevated PowerShell."
}

if ($Architecture -eq "auto") {
    $machine = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    $Architecture = if ($machine -eq "arm64") { "arm64" } else { "x64" }
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

$keyName = if ($Architecture -eq "arm64") {
    "utm-render-dock-arm64-target-v1.pem"
} else {
    "utm-render-dock-x64-target-v1.pem"
}
$policyName = if ($Architecture -eq "arm64") {
    "utm-render-dock-windows-arm64-v1.json"
} else {
    "utm-render-dock-windows-x64-v1.json"
}

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
