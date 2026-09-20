param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Install', 'Collect')]
    [string]$Mode,

    [string]$InstallerPath = '',

    [string]$EvidenceRoot = "$env:ProgramData\BKE Digital Solutions\Licensing Agent\phase10-arm64-rollback"
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        throw 'Unable to resolve the certification script directory.'
    }
    $InstallerPath = Join-Path $PSScriptRoot 'BKE-Licensing-Agent-2.0.1-Windows-arm64.exe'
}

$ServiceName = 'BKE-Licensing-Agent'
$InstallRoot = 'C:\Program Files\BKE Digital Solutions\Licensing Agent'
$DataRoot = "$env:ProgramData\BKE Digital Solutions\Licensing Agent"
$ServiceExe = Join-Path $InstallRoot 'service\bke-licensing-agent-service.exe'
$RuntimeExe = Join-Path $InstallRoot 'runtime\bke-licensing-agent-runtime.exe'
$AgentDb = Join-Path $DataRoot 'agent.db'
$DurableMarker = Join-Path $DataRoot 'phase10-arm64-rollback-marker.txt'
$ExpectedPath = Join-Path $EvidenceRoot 'expected.json'
$ResultPath = Join-Path $EvidenceRoot 'result.json'
$InstallerLog = Join-Path $EvidenceRoot 'broken-update-installer.log'
$AuthorizeUri = 'http://127.0.0.1:43873/v1/authorize'
$AuthorizeBody = @{
    product_id = 'runtime-bridge-cert'
    version = '2.0.0'
    installation_id = 'runtime-bridge-installation'
} | ConvertTo-Json -Compress

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Phase 10 ARM64 rollback certification must run from an elevated PowerShell.'
    }
}

function Normalize-ExecutablePath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return $Value.Trim().Trim('"')
}

function Get-ServiceRecord {
    Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
}

function Get-FileSha256([string]$Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file is missing: $Path"
    }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Arm64Pe([string]$Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required ARM64 executable is missing: $Path"
    }
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path))
    if ($bytes.Length -lt 256) { throw "PE file is too small: $Path" }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if (($peOffset -lt 0) -or (($peOffset + 6) -gt $bytes.Length)) {
        throw "Invalid PE header offset: $Path"
    }
    $signature = 'PE' + [char]0 + [char]0
    if ([Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4) -ne $signature) {
        throw "Invalid PE signature: $Path"
    }
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    if ($machine -ne 0xAA64) {
        throw ("Expected native ARM64 PE 0xAA64 but found 0x{0:X4}: {1}" -f $machine, $Path)
    }
}

function Wait-ServiceRunning([int]$TimeoutSeconds = 90) {
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds($TimeoutSeconds))
}

function Get-RuntimeProcess {
    $record = Get-ServiceRecord
    if ([int]$record.ProcessId -le 0) { return $null }
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$($record.ProcessId)" -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -eq 'bke-licensing-agent-runtime.exe' -and
            (Normalize-ExecutablePath ([string]$_.ExecutablePath)) -eq $RuntimeExe
        } |
        Select-Object -First 1
}

function Wait-RuntimeProcess([int]$TimeoutSeconds = 90) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $runtime = Get-RuntimeProcess
        if ($runtime) { return $runtime }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $null
}

function Wait-AgentAuthorized([int]$TimeoutSeconds = 90) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-RestMethod -Method Post -Uri $AuthorizeUri -ContentType 'application/json' -Body $AuthorizeBody -TimeoutSec 3
            if ($response.authorized -eq $true -and $response.reason -eq 'authorized') {
                return $true
            }
        }
        catch {}
        Start-Sleep -Milliseconds 750
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Assert-LoopbackOwnedByRuntime([int]$RuntimePid) {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort 43873 -ErrorAction SilentlyContinue
    if (!$listeners) { throw 'Agent has no listening socket on port 43873.' }
    foreach ($listener in @($listeners)) {
        if ($listener.LocalAddress -notin @('127.0.0.1', '::1')) {
            throw "Agent port 43873 is listening outside loopback: $($listener.LocalAddress)"
        }
        if ([int]$listener.OwningProcess -ne $RuntimePid) {
            throw "Agent port 43873 is not owned by the supervised runtime. Listener PID=$($listener.OwningProcess), runtime PID=$RuntimePid"
        }
    }
}

function Assert-StableServiceIdentity {
    Wait-ServiceRunning
    $record = Get-ServiceRecord
    if ($record.StartMode -ne 'Auto') { throw "Agent service is not Automatic: $($record.StartMode)" }
    if ($record.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) {
        throw "Agent service is not LocalSystem: $($record.StartName)"
    }
    if ((Normalize-ExecutablePath ([string]$record.PathName)) -ne $ServiceExe) {
        throw "Stable SCM executable path drifted: $($record.PathName)"
    }
    return $record
}

function Write-Json([string]$Path, [System.Collections.IDictionary]$Document) {
    New-Item -ItemType Directory -Force (Split-Path -Parent $Path) | Out-Null
    $Document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding utf8
}

Assert-Administrator

if ($Mode -eq 'Prepare') {
    New-Item -ItemType Directory -Force $EvidenceRoot | Out-Null
    Remove-Item -LiteralPath $ResultPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $InstallerLog -Force -ErrorAction SilentlyContinue

    $resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
    if ([IO.Path]::GetFileName($resolvedInstaller) -ne 'BKE-Licensing-Agent-2.0.1-Windows-arm64.exe') {
        throw "Unexpected Phase 10 broken installer filename: $resolvedInstaller"
    }

    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    if (($os.OSArchitecture -notmatch 'ARM') -and ($computer.SystemType -notmatch 'ARM64')) {
        throw "This certification requires Windows ARM64. OSArchitecture=$($os.OSArchitecture) SystemType=$($computer.SystemType)"
    }

    $record = Assert-StableServiceIdentity
    Assert-Arm64Pe $ServiceExe
    Assert-Arm64Pe $RuntimeExe

    if (Test-Path -LiteralPath (Join-Path $InstallRoot 'bridge-cert.enable')) {
        throw 'Certification bridge marker unexpectedly exists on the canonical Phase 8 machine.'
    }
    if (!(Test-Path -LiteralPath $AgentDb -PathType Leaf)) {
        throw "Durable Agent database is missing before Phase 10 rollback test: $AgentDb"
    }
    foreach ($path in @((Join-Path $InstallRoot 'service.rollback'),(Join-Path $InstallRoot 'runtime.rollback'))) {
        if (Test-Path -LiteralPath $path) { throw "Rollback staging already exists before Phase 10: $path" }
    }
    if (!(Wait-AgentAuthorized 60)) {
        throw 'Durable signed authorization is not healthy before Phase 10 rollback test.'
    }

    $runtime = Wait-RuntimeProcess 60
    if (!$runtime) { throw 'Stable bootstrap is not supervising the runtime before Phase 10 rollback test.' }
    Assert-LoopbackOwnedByRuntime ([int]$runtime.ProcessId)

    $markerValue = "phase10-arm64-rollback|$([DateTimeOffset]::UtcNow.ToString('O'))"
    Set-Content -LiteralPath $DurableMarker -Value $markerValue -Encoding ascii

    $expected = [ordered]@{
        schema = 'bke.broken-update-rollback-arm64.v1'
        machine_name = $env:COMPUTERNAME
        prepared_at = [DateTimeOffset]::UtcNow.ToString('O')
        installer_path = $resolvedInstaller
        installer_sha256 = Get-FileSha256 $resolvedInstaller
        baseline_service_sha256 = Get-FileSha256 $ServiceExe
        baseline_runtime_sha256 = Get-FileSha256 $RuntimeExe
        agent_db_present = $true
        durable_marker = $DurableMarker
        durable_marker_value = $markerValue
        service_path = [string]$record.PathName
        service_start_mode = [string]$record.StartMode
        service_start_name = [string]$record.StartName
    }
    Write-Json $ExpectedPath $expected

    Write-Host 'Phase 10 ARM64 rollback preparation: PASS'
    Write-Host "Installer SHA256: $($expected.installer_sha256)"
    Write-Host "Baseline service SHA256: $($expected.baseline_service_sha256)"
    Write-Host "Baseline runtime SHA256: $($expected.baseline_runtime_sha256)"
    exit 0
}

if ($Mode -eq 'Install') {
    $result = [ordered]@{
        schema = 'bke.broken-update-rollback-arm64.v1'
        status = 'FAIL'
        verified_at = [DateTimeOffset]::UtcNow.ToString('O')
        machine_name = $env:COMPUTERNAME
        checks = [ordered]@{}
        error = $null
    }

    try {
        if (!(Test-Path -LiteralPath $ExpectedPath -PathType Leaf)) {
            throw "Phase 10 preparation evidence is missing: $ExpectedPath"
        }
        $expected = Get-Content -LiteralPath $ExpectedPath -Raw | ConvertFrom-Json
        if ($expected.schema -ne 'bke.broken-update-rollback-arm64.v1') {
            throw 'Unexpected Phase 10 preparation schema.'
        }
        if ($expected.machine_name -ne $env:COMPUTERNAME) {
            throw "Preparation belongs to a different machine: $($expected.machine_name)"
        }

        $resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
        if ((Get-FileSha256 $resolvedInstaller) -ne [string]$expected.installer_sha256) {
            throw 'Broken ARM64 installer hash changed after preparation.'
        }
        $result.checks['installer_identity_preserved'] = $true

        $arguments = @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="{0}"' -f $InstallerLog))
        $process = Start-Process -FilePath $resolvedInstaller -ArgumentList $arguments -Wait -PassThru
        $result['installer_exit_code'] = [int]$process.ExitCode
        if ($process.ExitCode -ne 0) {
            throw "Handled broken ARM64 update returned exit code $($process.ExitCode). See $InstallerLog"
        }
        $result.checks['installer_exit_zero'] = $true

        if (!(Test-Path -LiteralPath $InstallerLog -PathType Leaf)) {
            throw "Broken-update installer log is missing: $InstallerLog"
        }
        $log = Get-Content -LiteralPath $InstallerLog -Raw
        if (!$log.Contains('Replacement runtime failed health; previous Agent payload restored automatically.')) {
            throw 'Installer log does not prove automatic rollback completed.'
        }
        $result.checks['rollback_log_confirmed'] = $true

        $record = Assert-StableServiceIdentity
        $result.checks['service_running'] = $true
        $result.checks['service_identity_preserved'] = $true

        Assert-Arm64Pe $ServiceExe
        Assert-Arm64Pe $RuntimeExe
        $result.checks['native_arm64_payloads'] = $true

        $serviceHash = Get-FileSha256 $ServiceExe
        $runtimeHash = Get-FileSha256 $RuntimeExe
        if ($serviceHash -ne [string]$expected.baseline_service_sha256) {
            throw "Stable service payload was not restored byte-for-byte. expected=$($expected.baseline_service_sha256) actual=$serviceHash"
        }
        if ($runtimeHash -ne [string]$expected.baseline_runtime_sha256) {
            throw "Runtime payload was not restored byte-for-byte. expected=$($expected.baseline_runtime_sha256) actual=$runtimeHash"
        }
        $result.checks['payload_hashes_restored'] = $true

        if (!(Test-Path -LiteralPath $DurableMarker -PathType Leaf)) {
            throw 'Phase 10 durable ProgramData marker was lost.'
        }
        if ((Get-Content -LiteralPath $DurableMarker -Raw).Trim() -ne [string]$expected.durable_marker_value) {
            throw 'Phase 10 durable ProgramData marker changed.'
        }
        if (!(Test-Path -LiteralPath $AgentDb -PathType Leaf)) {
            throw 'Durable Agent database was lost during broken update rollback.'
        }
        if (!(Wait-AgentAuthorized 90)) {
            throw 'Durable signed authorization did not recover after rollback.'
        }
        $result.checks['durable_state_preserved'] = $true
        $result.checks['signed_authorization_recovered'] = $true

        foreach ($path in @((Join-Path $InstallRoot 'service.rollback'),(Join-Path $InstallRoot 'runtime.rollback'))) {
            if (Test-Path -LiteralPath $path) { throw "Rollback staging leaked after recovery: $path" }
        }
        $result.checks['rollback_staging_cleared'] = $true

        $runtime = Wait-RuntimeProcess 90
        if (!$runtime) { throw 'Runtime supervision did not recover after rollback.' }
        $result.checks['runtime_supervision_recovered'] = $true

        Assert-LoopbackOwnedByRuntime ([int]$runtime.ProcessId)
        $result.checks['loopback_boundary_preserved'] = $true

        $machineDataDir = [Environment]::GetEnvironmentVariable('BKE_AGENT_DATA_DIR', 'Machine')
        if ($machineDataDir -ne $DataRoot) {
            throw "Machine BKE_AGENT_DATA_DIR drifted: $machineDataDir"
        }
        $result.checks['data_root_contract_preserved'] = $true

        $result['service_sha256_after'] = $serviceHash
        $result['runtime_sha256_after'] = $runtimeHash
        $result['service_path_after'] = [string]$record.PathName
        $result['status'] = 'PASS'
    }
    catch {
        $result['error'] = $_.Exception.Message
    }
    finally {
        Write-Json $ResultPath $result
    }

    if ($result.status -ne 'PASS') {
        Write-Error "PHASE 10 ARM64 BROKEN-UPDATE ROLLBACK CERTIFICATION FAILED: $($result.error)"
        exit 1
    }

    Write-Host 'Phase 10 Windows ARM64 broken-update rollback: PASS'
    exit 0
}

if ($Mode -eq 'Collect') {
    if (!(Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
        throw "Phase 10 result is not available: $ResultPath"
    }
    $result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    $result | ConvertTo-Json -Depth 10
    if ($result.status -ne 'PASS') {
        throw "Phase 10 ARM64 rollback certification did not pass: $($result.error)"
    }
    exit 0
}
