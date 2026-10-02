param(
    [ValidateSet("all","x64","arm64")]
    [string]$Architecture = "all",

    [switch]$RemoveDigitalSolutionsSigningTrust
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


if ($RemoveDigitalSolutionsSigningTrust) {
    $envPath = Join-Path $dataRoot ".env"
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

    $signingMarker = Join-Path $dataRoot "UTM-TEST-ONLY-Digital-Solutions-signing-trust.txt"
    if (Test-Path -LiteralPath $signingMarker) {
        $values = @{}
        foreach ($line in Get-Content -LiteralPath $signingMarker) {
            $separator = $line.IndexOf("=")
            if ($separator -gt 0) {
                $values[$line.Substring(0, $separator).Trim()] = $line.Substring($separator + 1).Trim()
            }
        }
        $signingKeyId = [string]$values["key_id"]
        if ([string]::IsNullOrWhiteSpace($signingKeyId) -or
            $signingKeyId -notmatch "^[A-Za-z0-9._-]{1,128}$") {
            throw "Disposable signing-trust marker contains an invalid key id."
        }

        $trustedKeysDir = [IO.Path]::GetFullPath((Join-Path $dataRoot "trusted-keys"))
        $signingDestination = [IO.Path]::GetFullPath((Join-Path $trustedKeysDir ($signingKeyId + ".pem")))
        $agentDataRoot = [IO.Path]::GetFullPath($dataRoot)
        if (-not $signingDestination.StartsWith(
                $agentDataRoot + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "Disposable signing-trust path escaped the expected protected ProgramData root."
        }

        Remove-Item -LiteralPath $signingDestination -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $signingMarker -Force
        Write-Host "UTM TEST-ONLY Digital Solutions signing trust removed."
        Write-Host "key_id=$signingKeyId"
    } else {
        Write-Host "UTM TEST-ONLY Digital Solutions signing trust marker is already absent."
    }
}
