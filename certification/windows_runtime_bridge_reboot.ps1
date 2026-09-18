param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Verify', 'Collect')]
    [string]$Mode,

    [string]$EvidenceRoot = "$env:ProgramData\BKE Digital Solutions\Licensing Agent\reboot-certification",

    [switch]$NoReboot
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'BKE-Licensing-Agent'
$TaskName = 'BKE-Licensing-Agent-Reboot-Certification'
$InstallRoot = 'C:\Program Files\BKE Digital Solutions\Licensing Agent'
$ServiceExe = Join-Path $InstallRoot 'service\bke-licensing-agent-service.exe'
$RuntimeExe = Join-Path $InstallRoot 'runtime\bke-licensing-agent-runtime.exe'
$BridgeMarker = Join-Path $InstallRoot 'bridge-cert.enable'
$ExpectedPath = Join-Path $EvidenceRoot 'expected.json'
$ResultPath = Join-Path $EvidenceRoot 'result.json'
$VerifierPath = Join-Path $EvidenceRoot 'windows_runtime_bridge_reboot.ps1'
$AuthorizeUri = 'http://127.0.0.1:43873/v1/authorize'
$AuthorizeBody = @{
    product_id = 'runtime-bridge-cert'
    version = '2.0.0'
    installation_id = 'runtime-bridge-installation'
} | ConvertTo-Json -Compress

function Get-BootTime {
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
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

function Wait-AgentAuthorized([int]$TimeoutSeconds = 180) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-RestMethod -Method Post -Uri $AuthorizeUri -ContentType 'application/json' -Body $AuthorizeBody -TimeoutSec 3
            if ($response.authorized -eq $true -and $response.reason -eq 'authorized') {
                return $true
            }
        }
        catch {
            # Boot-time verification deliberately waits for SCM + runtime startup.
        }
        Start-Sleep -Milliseconds 1000
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Get-RuntimeProcess {
    Get-CimInstance Win32_Process |
        Where-Object { $_.ExecutablePath -eq $RuntimeExe } |
        Select-Object -First 1
}

function Assert-LoopbackOnly {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort 43873 -ErrorAction SilentlyContinue
    if (!$listeners) {
        throw 'Agent has no listening socket on port 43873.'
    }
    $bad = $listeners | Where-Object {
        $_.LocalAddress -notin @('127.0.0.1', '::1')
    }
    if ($bad) {
        throw "Agent port 43873 is listening outside loopback: $($bad.LocalAddress -join ', ')"
    }
}

function Write-Result([hashtable]$Document) {
    New-Item -ItemType Directory -Force $EvidenceRoot | Out-Null
    $Document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResultPath -Encoding utf8
}

if ($Mode -eq 'Prepare') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Reboot certification preparation must run elevated.'
    }

    New-Item -ItemType Directory -Force $EvidenceRoot | Out-Null
    Remove-Item -LiteralPath $ResultPath -Force -ErrorAction SilentlyContinue

    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    $record = Get-ServiceRecord

    if ($record.StartMode -ne 'Auto') {
        throw "Agent service is not Automatic before reboot: $($record.StartMode)"
    }
    if ($record.PathName -notmatch 'service\\bke-licensing-agent-service\.exe') {
        throw "Stable SCM path drifted before reboot: $($record.PathName)"
    }
    if ($record.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) {
        throw "Agent service is not running as LocalSystem before reboot: $($record.StartName)"
    }
    if (!(Test-Path -LiteralPath $BridgeMarker)) {
        throw 'Certification bridge marker is missing before reboot.'
    }
    if (!(Wait-AgentAuthorized 60)) {
        throw 'Signed runtime-bridge fixture is not authorized before reboot.'
    }
    if (!(Get-RuntimeProcess)) {
        throw 'Stable bootstrap is not supervising the Gen2 runtime before reboot.'
    }
    Assert-LoopbackOnly

    $expected = [ordered]@{
        schema = 'bke.runtime-bridge-reboot.v1'
        machine_name = $env:COMPUTERNAME
        prepared_at = [DateTimeOffset]::UtcNow.ToString('O')
        boot_time_before = (Get-BootTime).ToString('O')
        service_path = $record.PathName
        service_start_mode = $record.StartMode
        service_start_name = $record.StartName
        service_sha256 = Get-FileSha256 $ServiceExe
        runtime_sha256 = Get-FileSha256 $RuntimeExe
        bridge_marker_sha256 = Get-FileSha256 $BridgeMarker
        authorize_product_id = 'runtime-bridge-cert'
        authorize_version = '2.0.0'
        authorize_installation_id = 'runtime-bridge-installation'
    }
    $expected | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ExpectedPath -Encoding utf8

    Copy-Item -LiteralPath $PSCommandPath -Destination $VerifierPath -Force

    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $VerifierPath +
        '" -Mode Verify -EvidenceRoot "' + $EvidenceRoot + '"'
    )
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    Write-Host "Reboot certification armed. Evidence root: $EvidenceRoot"
    Write-Host "Boot before: $($expected.boot_time_before)"

    if ($NoReboot) {
        Write-Host 'NoReboot specified; machine restart was not initiated.'
        exit 0
    }

    Write-Host 'Initiating a real Windows reboot in 10 seconds.'
    & "$env:SystemRoot\System32\shutdown.exe" /r /t 10 /f /d p:0:0 /c "BKE Licensing Agent reboot certification"
    if ($LASTEXITCODE -ne 0) {
        throw "Windows reboot request failed with exit code $LASTEXITCODE."
    }
    exit 0
}

if ($Mode -eq 'Verify') {
    $result = [ordered]@{
        schema = 'bke.runtime-bridge-reboot.v1'
        status = 'FAIL'
        verified_at = [DateTimeOffset]::UtcNow.ToString('O')
        machine_name = $env:COMPUTERNAME
        checks = [ordered]@{}
        error = $null
    }

    try {
        if (!(Test-Path -LiteralPath $ExpectedPath)) {
            throw "Expected reboot evidence is missing: $ExpectedPath"
        }
        $expected = Get-Content -LiteralPath $ExpectedPath -Raw | ConvertFrom-Json
        if ($expected.schema -ne 'bke.runtime-bridge-reboot.v1') {
            throw 'Unexpected reboot evidence schema.'
        }
        if ($expected.machine_name -ne $env:COMPUTERNAME) {
            throw "Reboot verification is running on a different machine: $env:COMPUTERNAME"
        }

        $before = [DateTimeOffset]::Parse([string]$expected.boot_time_before).UtcDateTime
        $after = Get-BootTime
        if ($after -le $before) {
            throw "Windows boot time did not advance. Before=$before After=$after"
        }
        $result.checks.boot_time_advanced = $true
        $result.boot_time_before = $before.ToString('O')
        $result.boot_time_after = $after.ToString('O')

        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(180))
        $record = Get-ServiceRecord
        if ($record.StartMode -ne 'Auto') {
            throw "Agent service is not Automatic after reboot: $($record.StartMode)"
        }
        if ($record.PathName -ne [string]$expected.service_path) {
            throw "Stable SCM path changed across reboot: $($record.PathName)"
        }
        if ($record.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) {
            throw "Agent service authority changed across reboot: $($record.StartName)"
        }
        $result.checks.service_running = $true
        $result.checks.service_identity_preserved = $true

        if ((Get-FileSha256 $ServiceExe) -ne [string]$expected.service_sha256) {
            throw 'Stable bootstrap binary changed across reboot.'
        }
        if ((Get-FileSha256 $RuntimeExe) -ne [string]$expected.runtime_sha256) {
            throw 'Gen2 runtime binary changed across reboot.'
        }
        if ((Get-FileSha256 $BridgeMarker) -ne [string]$expected.bridge_marker_sha256) {
            throw 'Runtime bridge certification marker changed across reboot.'
        }
        $result.checks.payload_hashes_preserved = $true

        if (!(Wait-AgentAuthorized 180)) {
            throw 'Signed runtime-bridge fixture did not authorize after real reboot.'
        }
        $result.checks.durable_authorization_recovered = $true

        if (!(Get-RuntimeProcess)) {
            throw 'Stable bootstrap is not supervising the Gen2 runtime after reboot.'
        }
        $result.checks.runtime_supervision_recovered = $true

        Assert-LoopbackOnly
        $result.checks.loopback_boundary_preserved = $true

        $result.status = 'PASS'
    }
    catch {
        $result.error = $_.Exception.Message
    }
    finally {
        Write-Result $result
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    if ($result.status -ne 'PASS') {
        Write-Error "REAL REBOOT CERTIFICATION FAILED: $($result.error)"
        exit 1
    }

    Write-Host 'Real Windows reboot -> installed Gen2 service + durable authorization: PASS'
    exit 0
}

if ($Mode -eq 'Collect') {
    if (!(Test-Path -LiteralPath $ResultPath)) {
        throw "Reboot certification result is not available: $ResultPath"
    }
    $result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    $result | ConvertTo-Json -Depth 8
    if ($result.status -ne 'PASS') {
        throw "Reboot certification did not pass: $($result.error)"
    }
    exit 0
}
