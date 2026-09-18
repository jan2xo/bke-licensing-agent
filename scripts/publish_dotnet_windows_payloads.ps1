param(
    [string]$Version = "2.0.0",
    [ValidateSet("x64", "arm64", "all")]
    [string]$Architecture = "all"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist\windows"

function Publish-Payload([string]$Project, [string]$Runtime, [string]$Output) {
    $outputPath = Join-Path $dist $Output
    Remove-Item -LiteralPath $outputPath -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $outputPath | Out-Null
    & dotnet publish (Join-Path $root $Project) --configuration Release --runtime $Runtime --self-contained true "-p:Version=$Version" --output $outputPath
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed: $Project ($Runtime)"
    }
}

function Publish-Architecture([string]$Name, [string]$Runtime) {
    Publish-Payload "dotnet\src\BKE.LicensingAgent.Desktop\BKE.LicensingAgent.Desktop.csproj" $Runtime "bke-license-center-$Name"
    Publish-Payload "dotnet\src\BKE.LicensingAgent.Updater\BKE.LicensingAgent.Updater.csproj" $Runtime "bke-updater-core-$Name"
    Publish-Payload "dotnet\src\BKE.LicensingAgent.Provisioner\BKE.LicensingAgent.Provisioner.csproj" $Runtime "bke-privileged-provisioner-$Name"

    foreach ($required in @(
        (Join-Path $dist "bke-license-center-$Name\bke-license-center.exe"),
        (Join-Path $dist "bke-updater-core-$Name\bke-updater-core.exe"),
        (Join-Path $dist "bke-privileged-provisioner-$Name\bke-privileged-provisioner.exe")
    )) {
        if (!(Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "required .NET payload missing: $required"
        }
    }
}

if ($Architecture -in @("x64", "all")) {
    Publish-Architecture "x64" "win-x64"
}
if ($Architecture -in @("arm64", "all")) {
    Publish-Architecture "arm64" "win-arm64"
}

Write-Host "BKE .NET-only Windows support payloads published: $Architecture"
