#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

dotnet build dotnet/src/BKE.LicensingAgent.Host/BKE.LicensingAgent.Host.csproj --configuration Release
dotnet build dotnet/certification/BKE.LicensingAgent.ContractCertification/BKE.LicensingAgent.ContractCertification.csproj --configuration Release
dotnet run --project dotnet/certification/BKE.LicensingAgent.ContractCertification/BKE.LicensingAgent.ContractCertification.csproj --configuration Release --no-build

PYTHONPATH=src python dotnet/certification/python_dotnet_differential.py
PYTHONPATH=src python dotnet/certification/authorization_differential.py
PYTHONPATH=src python dotnet/certification/activation_differential.py
PYTHONPATH=src python dotnet/certification/license_center_differential.py
PYTHONPATH=src python dotnet/certification/notification_differential.py
PYTHONPATH=src python dotnet/certification/update_differential.py
python -m pytest -q \
  tests/unit/test_local_api.py \
  tests/unit/test_license_center.py \
  tests/unit/test_license_center_service.py \
  tests/unit/test_native_license_center_launcher.py \
  tests/unit/test_notifications.py \
  tests/unit/test_notification_feed_provider.py \
  tests/unit/test_product_broadcast_sync.py \
  tests/unit/test_update_capability.py \
  tests/unit/test_update_discovery.py \
  tests/integration/test_platform_activation_http.py
