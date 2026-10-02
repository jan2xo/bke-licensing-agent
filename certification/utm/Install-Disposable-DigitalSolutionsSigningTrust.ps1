[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PublicKeyPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[A-Za-z0-9._-]{1,128}$")]
    [string]$KeyId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{64}$")]
    [string]$ExpectedSha256,

    [switch]$Force
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this UTM TEST-ONLY signing-trust installer from an elevated PowerShell."
}

$dataRoot = Join-Path $env:ProgramData "BKE Digital Solutions\Licensing Agent"
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

$source = (Resolve-Path -LiteralPath $PublicKeyPath).Path
$content = [IO.File]::ReadAllText($source)
if ($content.Contains("BEGIN PRIVATE KEY") -or
    $content.Contains("BEGIN ED25519 PRIVATE KEY")) {
    throw "Refusing signing trust input that contains private-key material."
}
if (-not $content.Contains("BEGIN PUBLIC KEY") -or
    -not $content.Contains("END PUBLIC KEY")) {
    throw "Disposable signing trust input must be a PEM public key."
}

$actualSha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -cne $ExpectedSha256.ToLowerInvariant()) {
    throw "Disposable signing public-key SHA-256 does not match the pinned operator value."
}

$trustedKeysDir = [IO.Path]::GetFullPath((Join-Path $dataRoot "trusted-keys"))
$expectedRoot = [IO.Path]::GetFullPath($dataRoot)
if (-not $trustedKeysDir.StartsWith(
        $expectedRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "Agent trusted-key path escaped the expected protected ProgramData root."
}

New-Item -ItemType Directory -Force -Path $trustedKeysDir | Out-Null
$destination = Join-Path $trustedKeysDir ($KeyId + ".pem")

if ((Test-Path -LiteralPath $destination) -and -not $Force) {
    $existingSha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($existingSha256 -cne $actualSha256) {
        throw "A different trusted public key already exists for '$KeyId'. Use -Force only for an intentional disposable UTM replacement."
    }
} else {
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

$installedSha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
if ($installedSha256 -cne $actualSha256) {
    throw "Installed disposable signing public key failed SHA-256 verification."
}

$marker = Join-Path $dataRoot "UTM-TEST-ONLY-Digital-Solutions-signing-trust.txt"
@"
UTM TEST ONLY
key_id=$KeyId
key_sha256=$installedSha256
platform_authority=$($platformUri.AbsoluteUri.TrimEnd('/'))
installed_at=$([DateTimeOffset]::UtcNow.ToString("O"))
DO NOT USE THIS SIGNING TRUST FOR PRODUCTION.
"@ | Set-Content -LiteralPath $marker -Encoding utf8

Write-Host "UTM TEST-ONLY Digital Solutions signing trust installed."
Write-Host "key_id=$KeyId"
Write-Host "key_sha256=$installedSha256"
Write-Host "production_authority_blocked=true"
