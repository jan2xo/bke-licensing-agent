param(
    [ValidateSet("all","x64","arm64")]
    [string]$Architecture = "all"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this UTM TEST-ONLY trust removal from an elevated PowerShell."
}

$dataRoot = Join-Path $env:ProgramData "BKE Digital Solutions\Licensing Agent"
$configPath = Join-Path $dataRoot "privileged-update.json"
if (!(Test-Path $configPath)) {
    throw "BKE Licensing Agent privileged configuration is unavailable."
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

$targets = @()
if ($Architecture -in @("all","x64")) {
    $targets += @(
        (Join-Path $keyDir "utm-render-dock-x64-target-v1.pem"),
        (Join-Path $policyDir "utm-render-dock-windows-x64-v1.json")
    )
}
if ($Architecture -in @("all","arm64")) {
    $targets += @(
        (Join-Path $keyDir "utm-render-dock-arm64-target-v1.pem"),
        (Join-Path $policyDir "utm-render-dock-windows-arm64-v1.json")
    )
}

foreach ($path in $targets) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}

Remove-Item -LiteralPath (Join-Path $dataRoot "UTM-TEST-ONLY-Render-Dock-target-trust.txt") -Force -ErrorAction SilentlyContinue
Write-Host "UTM TEST-ONLY Render Dock target trust removed."
