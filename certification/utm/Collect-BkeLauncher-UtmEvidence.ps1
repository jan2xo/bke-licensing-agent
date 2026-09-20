[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\BKE-UTM-EVIDENCE"
)

$ErrorActionPreference = "Stop"
$baseUri = "http://127.0.0.1:43873"

if (Test-Path $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null

function Write-JsonEvidence([string]$Name, [object]$Value) {
    $Value | ConvertTo-Json -Depth 16 |
        Set-Content -LiteralPath (Join-Path $OutputDirectory $Name) -Encoding utf8
}

function Invoke-AgentPost([string]$Path, [object]$Body) {
    try {
        return Invoke-RestMethod -Method Post -Uri ($baseUri + $Path) -ContentType "application/json" -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 10
    } catch {
        return [ordered]@{
            probe_error = $_.Exception.Message
            path = $Path
        }
    }
}

$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
Write-JsonEvidence "01-machine.json" ([ordered]@{
    captured_at = [DateTimeOffset]::UtcNow.ToString("O")
    architecture = $architecture
    os = $os
    machine_name = $env:COMPUTERNAME
})

$service = Get-CimInstance Win32_Service -Filter "Name='BKE-Licensing-Agent'" -ErrorAction SilentlyContinue
Write-JsonEvidence "02-agent-service.json" ([ordered]@{
    exists = $null -ne $service
    state = if ($service) { $service.State } else { $null }
    start_mode = if ($service) { $service.StartMode } else { $null }
    start_name = if ($service) { $service.StartName } else { $null }
    path_name = if ($service) { $service.PathName } else { $null }
    process_id = if ($service) { $service.ProcessId } else { $null }
})

$health = try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$baseUri/license-center?product_id=utm-health&version=1.0.0&installation_id=utm-health" -TimeoutSec 5
    [ordered]@{
        status_code = $r.StatusCode
        healthy = ($r.StatusCode -eq 200)
    }
} catch {
    [ordered]@{
        healthy = $false
        error = $_.Exception.Message
    }
}
Write-JsonEvidence "03-agent-health.json" $health

$session = Invoke-AgentPost "/v1/account-session/status" ([ordered]@{
    correlation_id = "utm-evidence-" + [Guid]::NewGuid().ToString("N")
})
Write-JsonEvidence "04-account-session.json" $session

$catalog = Invoke-AgentPost "/v1/software/catalog" ([ordered]@{
    correlation_id = "utm-catalog-" + [Guid]::NewGuid().ToString("N")
})
Write-JsonEvidence "05-software-catalog.json" $catalog

$configPath = Join-Path $env:ProgramData "BKE Digital Solutions\Licensing Agent\privileged-update.json"
$configEvidence = [ordered]@{
    exists = Test-Path $configPath
}
if (Test-Path $configPath) {
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $configEvidence.runtime_root = [string]$config.runtime_root
    $configEvidence.helper_executable = [string]$config.helper_executable
    $configEvidence.target_keys_dir = [string]$config.target_keys_dir
    $configEvidence.target_policies_dir = [string]$config.target_policies_dir
    $configEvidence.approved_install_roots = @($config.approved_install_roots)
    $configEvidence.helper_exists = Test-Path ([string]$config.helper_executable)
}
Write-JsonEvidence "06-privileged-config.json" $configEvidence

$trustMarker = Join-Path $env:ProgramData "BKE Digital Solutions\Licensing Agent\UTM-TEST-ONLY-Render-Dock-target-trust.txt"
Write-JsonEvidence "07-utm-target-trust.json" ([ordered]@{
    marker_exists = Test-Path $trustMarker
    marker = if (Test-Path $trustMarker) {
        Get-Content -LiteralPath $trustMarker -Raw
    } else {
        $null
    }
})

$agentEnvPath = Join-Path $env:ProgramData "BKE Digital Solutions\Licensing Agent\.env"
$environmentEvidence = [ordered]@{
    exists = Test-Path $agentEnvPath
    environment = $null
    platform_scheme = $null
    platform_host = $null
    production_authority = $null
}
if (Test-Path $agentEnvPath) {
    $safeValues = @{}
    foreach ($line in Get-Content -LiteralPath $agentEnvPath) {
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
            $safeValues[$name] = $trimmed.Substring($separator + 1).Trim().Trim('"').Trim("'")
        }
    }

    $environmentEvidence.environment = $safeValues["BKE_ENVIRONMENT"]
    if ($safeValues.ContainsKey("BKE_PLATFORM_BASE_URL")) {
        $platformUri = $null
        if ([Uri]::TryCreate(
            $safeValues["BKE_PLATFORM_BASE_URL"],
            [UriKind]::Absolute,
            [ref]$platformUri
        )) {
            $environmentEvidence.platform_scheme = $platformUri.Scheme
            $environmentEvidence.platform_host = $platformUri.Host
            $hostName = $platformUri.Host.TrimEnd(".")
            $environmentEvidence.production_authority =
                ($hostName -ieq "jl-bke.com") -or
                $hostName.EndsWith(".jl-bke.com", [StringComparison]::OrdinalIgnoreCase)
        }
    }
}
Write-JsonEvidence "08-agent-environment.json" $environmentEvidence

$productRoot = Join-Path $env:ProgramFiles "BKE Digital Solutions\Render Dock"
$entryPoint = Join-Path $productRoot "RENDER DOCK.exe"
Write-JsonEvidence "09-render-dock-local.json" ([ordered]@{
    product_root = $productRoot
    product_root_exists = Test-Path $productRoot
    entry_point_exists = Test-Path $entryPoint
    entry_point_sha256 = if (Test-Path $entryPoint) {
        (Get-FileHash -LiteralPath $entryPoint -Algorithm SHA256).Hash.ToLowerInvariant()
    } else {
        $null
    }
})

Get-ChildItem -LiteralPath $OutputDirectory -File |
    Sort-Object Name |
    ForEach-Object {
        "{0}  {1}" -f ((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()), $_.Name
    } | Set-Content -LiteralPath (Join-Path $OutputDirectory "SHA256SUMS.txt") -Encoding ascii

Write-Host "BKE UTM evidence captured: $((Resolve-Path $OutputDirectory).Path)"
