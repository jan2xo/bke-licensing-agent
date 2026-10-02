[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this UTM TEST-ONLY signing-trust remover from an elevated PowerShell."
}

$dataRoot = Join-Path $env:ProgramData "BKE Digital Solutions\Licensing Agent"
$envPath = Join-Path $dataRoot ".env"
$marker = Join-Path $dataRoot "UTM-TEST-ONLY-Digital-Solutions-signing-trust.txt"

if (!(Test-Path -LiteralPath $envPath)) {
    throw "Agent UTM environment is unavailable."
}

$environment = $null
$platformBaseUrl = $null
foreach ($line in Get-Content -LiteralPath $envPath) {
    $trimmed = $line.Trim()
    if ($trimmed.StartsWith("BKE_ENVIRONMENT=")) {
        $environment = $trimmed.Substring("BKE_ENVIRONMENT=".Length).Trim().Trim('"').Trim("'")
    }
    if ($trimmed.StartsWith("BKE_PLATFORM_BASE_URL=")) {
        $platformBaseUrl = $trimmed.Substring("BKE_PLATFORM_BASE_URL=".Length).Trim().Trim('"').Trim("'")
    }
}

if ($environment -cne "utm") {
    throw "Disposable Digital Solutions signing trust may be removed only when BKE_ENVIRONMENT=utm."
}

$platformUri = $null
if (-not [Uri]::TryCreate($platformBaseUrl, [UriKind]::Absolute, [ref]$platformUri)) {
    throw "Agent UTM platform authority is invalid."
}
$platformHost = $platformUri.Host.TrimEnd(".")
if ($platformHost -ieq "jl-bke.com" -or
    $platformHost.EndsWith(".jl-bke.com", [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing disposable signing-trust removal while the Agent points at production authority."
}

if (!(Test-Path -LiteralPath $marker)) {
    Write-Host "UTM TEST-ONLY Digital Solutions signing trust marker is already absent."
    exit 0
}

$values = @{}
foreach ($line in Get-Content -LiteralPath $marker) {
    $separator = $line.IndexOf("=")
    if ($separator -gt 0) {
        $values[$line.Substring(0, $separator).Trim()] = $line.Substring($separator + 1).Trim()
    }
}
$keyId = [string]$values["key_id"]
if ([string]::IsNullOrWhiteSpace($keyId) -or
    $keyId -notmatch "^[A-Za-z0-9._-]{1,128}$") {
    throw "Disposable signing-trust marker contains an invalid key id."
}

$trustedKeysDir = [IO.Path]::GetFullPath((Join-Path $dataRoot "trusted-keys"))
$destination = [IO.Path]::GetFullPath((Join-Path $trustedKeysDir ($keyId + ".pem")))
$expectedRoot = [IO.Path]::GetFullPath($dataRoot)
if (-not $destination.StartsWith(
        $expectedRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "Disposable signing-trust path escaped the expected protected ProgramData root."
}

if (Test-Path -LiteralPath $destination) {
    Remove-Item -LiteralPath $destination -Force
}
Remove-Item -LiteralPath $marker -Force

Write-Host "UTM TEST-ONLY Digital Solutions signing trust removed."
Write-Host "key_id=$keyId"
