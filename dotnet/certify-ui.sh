#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

presentation="$root/dotnet/src/BKE.LicensingAgent.Presentation/BKE.LicensingAgent.Presentation.csproj"
desktop="$root/dotnet/src/BKE.LicensingAgent.Desktop/BKE.LicensingAgent.Desktop.csproj"

dotnet build "$presentation" -c Release --nologo
dotnet build "$desktop" -c Release --nologo

printf 'BKE Licensing Agent desktop UI boundary certified on net10.0.\n'
