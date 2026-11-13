# CI-ONLY source-to-source DS → Licensing Agent startup-policy interoperability.
# Uses the real DS test-signature implementation under mocked SQL and a
# per-process test Ed25519 key. No installed trust, customer credential, real
# DS origin or private signing material is ever installed or exported.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ExpectedDsSourceSha
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:RUNNER_OS -cne 'Windows' -or !$IsWindows -or
    !$env:RUNNER_TEMP -or
    $ExpectedDsSourceSha -cnotmatch '^[a-f0-9]{40}$') {
  throw 'DS startup interop is restricted to pinned disposable GitHub-hosted Windows.'
}
if ($env:DEPLOYMENT_ENV -ceq 'production') {
  throw 'Production DS authority is NEVER allowed in source interop.'
}

$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$sourceSha=(git -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceSha -cne $env:SOURCE_SHA -or
    $sourceSha -cnotmatch '^[a-f0-9]{40}$') {
  throw 'Current Licensing Agent source is not the exact certified Git SHA.'
}
$root=Join-Path $env:RUNNER_TEMP ('bke-source-interop-'+[Guid]::NewGuid().ToString('N'))
$ds=Join-Path $root 'ds'
$vector=Join-Path $root 'public-ds-signed-vector.json'
$npmLog=Join-Path $root 'npm-ci-log.txt'
$old=@{
  deployment=$env:DEPLOYMENT_ENV
  node=$env:NODE_ENV
  vector=$env:BKE_DS_STARTUP_INTEROP_VECTOR
  sha=$env:BKE_DS_STARTUP_INTEROP_SOURCE_SHA
}

try {
  New-Item -ItemType Directory -Path $ds -Force | Out-Null
  & git -C $ds init --quiet
  if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize isolated DS test checkout.' }
  & git -C $ds remote add origin 'https://github.com/jan2xo/bke-digital-solutions.git'
  if ($LASTEXITCODE -ne 0) { throw 'Cannot select canonical DS source origin.' }
  & git -C $ds fetch --quiet --depth 1 origin $ExpectedDsSourceSha
  if ($LASTEXITCODE -ne 0) { throw 'Cannot fetch exact merged DS source SHA.' }
  & git -C $ds checkout --quiet --detach FETCH_HEAD
  if ($LASTEXITCODE -ne 0 -or
      (git -C $ds rev-parse HEAD).Trim() -cne $ExpectedDsSourceSha) {
    throw 'DS source checkout drift: refuse to consume an unpinned signer.'
  }
  Push-Location $ds
  try {
    $nodeVersion=(& node --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch '^v(2[2-9]|[3-9][0-9])\.') {
      throw 'DS signer fixture requires installed Node 22 or newer.'
    }
    # No runtime environment file, secrets, signed commercial credential,
    # production DB, or issue/checkout route is invoked. npm output is retained
    # only under RUNNER_TEMP and removed before the runner is destroyed.
    $env:DEPLOYMENT_ENV='certification'
    $env:NODE_ENV='test'
    & npm.cmd ci --include=dev --no-audit --no-fund *> $npmLog
    if ($LASTEXITCODE -ne 0) {
      throw 'Pinned DS test dependencies did not restore; no fixture was trusted.'
    }
    if (Test-Path -LiteralPath $vector) {
      throw 'Refusing to overwrite any existing public DS test fixture.'
    }
    $env:BKE_DS_STARTUP_INTEROP_SOURCE_SHA=$ExpectedDsSourceSha
    $env:BKE_DS_STARTUP_INTEROP_VECTOR=$vector
    & npx.cmd vitest run tests/agent-standalone-startup-policy-issuance.test.ts -t 'exports CI-only real DS signed bytes for the pinned Agent .NET verifier'
    if ($LASTEXITCODE -ne 0) { throw 'Real DS signer interop fixture test failed.' }
  }
  finally { Pop-Location }

  if (!(Test-Path -LiteralPath $vector -PathType Leaf)) {
    throw 'DS producer did not emit a signed public-only vector.'
  }
  $raw=Get-Content -LiteralPath $vector -Raw
  if ($raw -match 'PRIVATE KEY') { throw 'DS vector leaked signer private material.' }
  Push-Location $repo
  try {
    & dotnet run --project 'dotnet/certification/BKE.LicensingAgent.ContractCertification/BKE.LicensingAgent.ContractCertification.csproj' --configuration Release --no-build -- --verify-ds-startup-vector $vector $ExpectedDsSourceSha
    if ($LASTEXITCODE -ne 0) { throw 'Actual native Agent parser rejected real DS source-signed bytes.' }
  } finally { Pop-Location }
  Write-Host 'DS_TO_AGENT_SOURCE_INTEROP_PASS: real DS test signer → actual Agent Ed25519 installed policy parser; wrong mode/SID/image denied.'
}
finally {
  $env:DEPLOYMENT_ENV=$old.deployment
  $env:NODE_ENV=$old.node
  $env:BKE_DS_STARTUP_INTEROP_VECTOR=$old.vector
  $env:BKE_DS_STARTUP_INTEROP_SOURCE_SHA=$old.sha
  if (Test-Path -LiteralPath $root) {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
  }
}
