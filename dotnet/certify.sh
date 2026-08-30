#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Keep certification intelligence in source control. GitHub Actions only invokes this entry point.
dotnet build "$ROOT/src/BKE.LicensingAgent.Host/BKE.LicensingAgent.Host.csproj" -c Release --nologo
dotnet build "$ROOT/certification/BKE.LicensingAgent.ContractCertification/BKE.LicensingAgent.ContractCertification.csproj" -c Release --nologo
dotnet run --project "$ROOT/certification/BKE.LicensingAgent.ContractCertification/BKE.LicensingAgent.ContractCertification.csproj" -c Release --no-build
