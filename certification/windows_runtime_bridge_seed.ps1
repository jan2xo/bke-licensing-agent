param(
    [string]$DataRoot = "$env:ProgramData\BKE Digital Solutions\Licensing Agent"
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'BKE-Licensing-Agent'
$Seeder = Join-Path $PSScriptRoot 'bke-runtime-bridge-cert-seeder.exe'
$AuthorizeUri = 'http://127.0.0.1:43873/v1/authorize'
$AuthorizeBody = @{
    product_id = 'runtime-bridge-cert'
    version = '2.0.0'
    installation_id = 'runtime-bridge-installation'
} | ConvertTo-Json -Compress

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Runtime bridge certification seeding must run elevated.'
}

if (!(Test-Path -LiteralPath $Seeder -PathType Leaf)) {
    throw "Certification seeder is missing: $Seeder"
}

$service = Get-Service -Name $ServiceName -ErrorAction Stop
if ($service.Status -ne 'Running') {
    throw "Agent service must be Running before certification seeding. Current state: $($service.Status)"
}

Write-Host 'Stopping BKE Licensing Agent briefly to seed disposable signed certification authority.'
Stop-Service -Name $ServiceName -Force
(Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))

try {
    & $Seeder --data-root $DataRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Certification seeder failed with exit code $LASTEXITCODE."
    }
}
finally {
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

$deadline = (Get-Date).AddSeconds(60)
do {
    try {
        $response = Invoke-RestMethod -Method Post -Uri $AuthorizeUri -ContentType 'application/json' -Body $AuthorizeBody -TimeoutSec 3
        if ($response.authorized -eq $true -and $response.reason -eq 'authorized') {
            Write-Host 'Disposable signed runtime-bridge authorization: PASS'
            $response | Format-List *
            exit 0
        }
        Write-Host "Authorization not ready: $($response | ConvertTo-Json -Compress)"
    }
    catch {
        Write-Host "Agent authorization endpoint not ready: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds 1
} while ((Get-Date) -lt $deadline)

throw 'Disposable signed runtime-bridge fixture did not authorize after seeding.'
