[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\BKE-UTM-EVIDENCE",

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{40}$")]
    [string]$DigitalSolutionsSourceSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{40}$")]
    [string]$LauncherSourceSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{40}$")]
    [string]$AgentSourceSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{40}$")]
    [string]$DemoAppSourceSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-fA-F]{64}$")]
    [string]$ParentInstallerSha256,

    [string]$RenderDockProductId = "bke-render-dock",

    [string]$RenderDockVersion = "1.0.3",

    [string]$LauncherPluginProductId = "bke-trial-product",

    [string]$LauncherPluginVersion = "2.0.0",

    [switch]$RequireCustomerSoftwareReady
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

Write-JsonEvidence "00-stack-provenance.json" ([ordered]@{
    captured_at = [DateTimeOffset]::UtcNow.ToString("O")
    digital_solutions_source_sha = $DigitalSolutionsSourceSha.ToLowerInvariant()
    launcher_source_sha = $LauncherSourceSha.ToLowerInvariant()
    agent_source_sha = $AgentSourceSha.ToLowerInvariant()
    demo_app_source_sha = $DemoAppSourceSha.ToLowerInvariant()
    parent_installer_sha256 = $ParentInstallerSha256.ToLowerInvariant()
    certification_state = "PREPRODUCTION_DISPOSABLE_UTM"
})

$runtimeArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
$architecture = if ($null -ne $runtimeArchitecture) {
    $runtimeArchitecture.ToString()
} elseif (-not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITECTURE)) {
    $env:PROCESSOR_ARCHITECTURE
} else {
    "unknown"
}
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

$catalogItems = if ($null -ne $catalog.items) {
    @($catalog.items)
} else {
    @()
}

$renderDockMatches = @(
    $catalogItems | Where-Object {
        [string]$_.product_id -ceq $RenderDockProductId
    }
)
$pluginMatches = @(
    $catalogItems | Where-Object {
        [string]$_.product_id -ceq $LauncherPluginProductId
    }
)

$renderDockItem = if ($renderDockMatches.Count -eq 1) {
    $renderDockMatches[0]
} else {
    $null
}
$pluginItem = if ($pluginMatches.Count -eq 1) {
    $pluginMatches[0]
} else {
    $null
}

$pluginAuthorization = Invoke-AgentPost "/v1/software/launcher-plugin/authorize" ([ordered]@{
    correlation_id = "utm-plugin-authorize-" + [Guid]::NewGuid().ToString("N")
    product_id = $LauncherPluginProductId
    version = $LauncherPluginVersion
})
Write-JsonEvidence "05-launcher-plugin-authorization.json" $pluginAuthorization

$renderDockReady =
    [string]$catalog.status -ceq "READY" -and
    $renderDockMatches.Count -eq 1 -and
    [string]$renderDockItem.execution_type -ceq "STANDALONE" -and
    [bool]$renderDockItem.entitled -and
    [string]$renderDockItem.latest_version -ceq $RenderDockVersion

$launcherPluginCatalogReady =
    [string]$catalog.status -ceq "READY" -and
    $pluginMatches.Count -eq 1 -and
    [string]$pluginItem.execution_type -ceq "LAUNCHER_PLUGIN" -and
    [bool]$pluginItem.entitled -and
    [string]$pluginItem.latest_version -ceq $LauncherPluginVersion

$launcherPluginAuthorized =
    [string]$pluginAuthorization.status -ceq "AUTHORIZED" -and
    [bool]$pluginAuthorization.authorized -and
    [string]$pluginAuthorization.reason -ceq "authorized"

$customerSoftwareReady =
    $renderDockReady -and
    $launcherPluginCatalogReady -and
    $launcherPluginAuthorized

Write-JsonEvidence "05-customer-software-proof.json" ([ordered]@{
    render_dock = [ordered]@{
        product_id = $RenderDockProductId
        expected_version = $RenderDockVersion
        match_count = $renderDockMatches.Count
        execution_type = if ($renderDockItem) { [string]$renderDockItem.execution_type } else { $null }
        entitled = if ($renderDockItem) { [bool]$renderDockItem.entitled } else { $false }
        latest_version = if ($renderDockItem) { [string]$renderDockItem.latest_version } else { $null }
        ready = $renderDockReady
    }
    launcher_plugin = [ordered]@{
        product_id = $LauncherPluginProductId
        expected_version = $LauncherPluginVersion
        match_count = $pluginMatches.Count
        execution_type = if ($pluginItem) { [string]$pluginItem.execution_type } else { $null }
        entitled = if ($pluginItem) { [bool]$pluginItem.entitled } else { $false }
        latest_version = if ($pluginItem) { [string]$pluginItem.latest_version } else { $null }
        authorization_status = [string]$pluginAuthorization.status
        authorized = [bool]$pluginAuthorization.authorized
        authorization_reason = [string]$pluginAuthorization.reason
        catalog_ready = $launcherPluginCatalogReady
        authorization_ready = $launcherPluginAuthorized
    }
    customer_software_ready = $customerSoftwareReady
})

if ($RequireCustomerSoftwareReady -and -not $customerSoftwareReady) {
    throw "Customer software proof is not ready. Inspect 05-software-catalog.json, 05-launcher-plugin-authorization.json, and 05-customer-software-proof.json."
}

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
$markerExists = [IO.File]::Exists($trustMarker)
$markerContent = if ($markerExists) {
    [IO.File]::ReadAllText($trustMarker)
} else {
    $null
}
Write-JsonEvidence "07-utm-target-trust.json" ([ordered]@{
    marker_exists = $markerExists
    marker = $markerContent
})

$agentEnvPath = Join-Path $env:ProgramData "BKE Digital Solutions\Licensing Agent\.env"
$expectedPlatformBaseUrl = $null
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
        $expectedPlatformBaseUrl = [string]$safeValues["BKE_PLATFORM_BASE_URL"]
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

$platformAuthority = Invoke-AgentPost "/v1/runtime/platform-authority" ([ordered]@{
    correlation_id = "utm-authority-" + [Guid]::NewGuid().ToString("N")
})
$authorityBaseUrl = if ($null -ne $platformAuthority.platform_base_url) {
    [string]$platformAuthority.platform_base_url
} else {
    $null
}
$authorityEnvironment = if ($null -ne $platformAuthority.environment) {
    [string]$platformAuthority.environment
} else {
    $null
}
$authorityMatchesEnvironment =
    [string]$platformAuthority.status -eq "READY" -and
    -not [string]::IsNullOrWhiteSpace($expectedPlatformBaseUrl) -and
    -not [string]::IsNullOrWhiteSpace($authorityBaseUrl) -and
    $authorityBaseUrl.TrimEnd("/") -ceq $expectedPlatformBaseUrl.TrimEnd("/") -and
    $authorityEnvironment -ceq [string]$environmentEvidence.environment

Write-JsonEvidence "08-agent-platform-authority.json" ([ordered]@{
    response = $platformAuthority
    matches_agent_environment = $authorityMatchesEnvironment
})

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

$bkeRoot = Join-Path $env:ProgramFiles "BKE Digital Solutions\BKE"
$bkeEntryPoint = Join-Path $bkeRoot "bke-launcher.exe"
$bkeItem = if (Test-Path $bkeEntryPoint -PathType Leaf) {
    Get-Item -LiteralPath $bkeEntryPoint
} else {
    $null
}
Write-JsonEvidence "10-bke-installation.json" ([ordered]@{
    bke_root = $bkeRoot
    bke_root_exists = Test-Path $bkeRoot
    launcher_exists = $null -ne $bkeItem
    launcher_sha256 = if ($bkeItem) {
        (Get-FileHash -LiteralPath $bkeItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    } else {
        $null
    }
    launcher_file_version = if ($bkeItem) { $bkeItem.VersionInfo.FileVersion } else { $null }
    launcher_product_version = if ($bkeItem) { $bkeItem.VersionInfo.ProductVersion } else { $null }
})

$notifications = Invoke-AgentPost "/v1/notifications/account-feed" ([ordered]@{
    limit = 50
})
Write-JsonEvidence "11-notification-inbox.json" $notifications

Get-ChildItem -LiteralPath $OutputDirectory -File |
    Sort-Object Name |
    ForEach-Object {
        "{0}  {1}" -f ((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()), $_.Name
    } | Set-Content -LiteralPath (Join-Path $OutputDirectory "SHA256SUMS.txt") -Encoding ascii

Write-Host "BKE UTM evidence captured: $((Resolve-Path $OutputDirectory).Path)"
