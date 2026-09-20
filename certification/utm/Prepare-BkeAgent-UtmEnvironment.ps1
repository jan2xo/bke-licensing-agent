[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PlatformBaseUrl,

    [switch]$AllowInsecureLoopback,

    [switch]$Force
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this UTM environment preparation from an elevated PowerShell."
}

$uri = $null
if (-not [Uri]::TryCreate($PlatformBaseUrl, [UriKind]::Absolute, [ref]$uri)) {
    throw "PlatformBaseUrl must be an absolute URL."
}

if ($uri.Scheme -notin @("http", "https") -or
    -not [string]::IsNullOrEmpty($uri.Query) -or
    -not [string]::IsNullOrEmpty($uri.Fragment)) {
    throw "PlatformBaseUrl must use HTTP(S) without query or fragment."
}

$hostName = $uri.Host.TrimEnd(".")
if ($hostName -ieq "jl-bke.com" -or
    $hostName.EndsWith(".jl-bke.com", [StringComparison]::OrdinalIgnoreCase)) {
    throw "UTM environment refuses the production jl-bke.com authority."
}

if ($uri.Scheme -eq "http") {
    $isLoopback = $hostName -in @("127.0.0.1", "::1", "localhost")
    if (-not $AllowInsecureLoopback -or -not $isLoopback) {
        throw "HTTP is allowed only for explicit loopback UTM testing with -AllowInsecureLoopback."
    }
}

$dataRoot = Join-Path $env:ProgramData "BKE Digital Solutions\Licensing Agent"
$envPath = Join-Path $dataRoot ".env"

if ((Test-Path -LiteralPath $envPath) -and -not $Force) {
    throw "Agent .env already exists. Use -Force only when intentionally replacing disposable UTM configuration."
}

New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null

$lines = @(
    "BKE_ENVIRONMENT=utm",
    "BKE_PLATFORM_BASE_URL=$($uri.AbsoluteUri.TrimEnd('/'))"
)

if ($uri.Scheme -eq "http") {
    $lines += "BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL=1"
}

$content = ($lines -join [Environment]::NewLine) + [Environment]::NewLine
[IO.File]::WriteAllText(
    $envPath,
    $content,
    [Text.UTF8Encoding]::new($false)
)

Write-Host "BKE Agent UTM environment prepared."
Write-Host "path=$envPath"
Write-Host "environment=utm"
Write-Host "platform_host=$hostName"
Write-Host "production_authority_blocked=true"
