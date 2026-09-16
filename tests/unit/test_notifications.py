import json
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from bke_licensing_agent.license_center.native_launcher import NativeLicenseCenterLauncher
from bke_licensing_agent.license_center.service import (
    LicenseCenterAction,
    LicenseCenterOutcome,
    OpenLicenseCenterRequest,
)
from bke_licensing_agent.local_api import LocalAuthorizationServer
from bke_licensing_agent.manifest.validator import validate_manifest
from bke_licensing_agent.notifications import (
    AgentNotificationService,
    NotificationCode,
)
from bke_licensing_agent.runtime import InstalledAgentRuntime
from bke_licensing_agent.storage.database import Database


def _manifest():
    return validate_manifest({
        "schemaVersion": 1,
        "productId": "demo",
        "displayName": "Demo",
        "version": "1.0.0",
        "entryPoint": "demo.exe",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    })


def test_typed_notifications_persist_dedupe_scope_and_dismiss(tmp_path: Path):
    with Database(tmp_path / "agent.db") as database:
        service = AgentNotificationService(database)
        first = service.ensure("product-a", NotificationCode.LICENSE_REQUIRED)
        second = service.ensure("product-a", NotificationCode.LICENSE_REQUIRED)

        assert first.notification_id == second.notification_id
        assert len(service.list_for_product("product-a")) == 1
        assert service.list_for_product("product-b") == ()
        assert service.dismiss(first.notification_id) is True
        assert service.dismiss(first.notification_id) is False
        assert service.list_for_product("product-a") == ()

        dismissed = service.list_for_product("product-a", include_dismissed=True)
        assert len(dismissed) == 1
        assert dismissed[0].state == "dismissed"


def test_notification_presentation_is_agent_owned_and_contains_no_remote_content():
    presentation = AgentNotificationService.presentation(NotificationCode.LICENSE_REQUIRED)
    assert presentation.title == "License required"
    assert "commercial license" in presentation.body.lower()
    assert "http" not in presentation.body.lower()
    assert "<" not in presentation.body and ">" not in presentation.body


def test_runtime_accepts_only_authoritative_license_required_notice(tmp_path: Path):
    with Database(tmp_path / "agent.db") as database:
        runtime = object.__new__(InstalledAgentRuntime)
        runtime.notifications = AgentNotificationService(database)
        runtime._validated_product = lambda product_id, version: _manifest() if (product_id, version) == ("demo", "1.0.0") else None
        runtime.authorize = lambda request: {"authorized": False, "reason": "activation_required"}

        accepted = runtime.request_notification({
            "product_id": "demo",
            "version": "1.0.0",
            "installation_id": "install-1",
            "code": "LICENSE_REQUIRED",
        })
        assert accepted["status"] == "accepted"
        assert accepted["code"] == "LICENSE_REQUIRED"

        runtime.authorize = lambda request: {"authorized": True, "reason": "ALLOW"}
        assert runtime.request_notification({
            "product_id": "demo", "version": "1.0.0",
            "installation_id": "install-1", "code": "LICENSE_REQUIRED",
        }) == {"status": "rejected", "reason": "product_already_authorized"}

        runtime.authorize = lambda request: {"authorized": False, "reason": "trusted_keys_unavailable"}
        assert runtime.request_notification({
            "product_id": "demo", "version": "1.0.0",
            "installation_id": "install-1", "code": "LICENSE_REQUIRED",
        }) == {"status": "rejected", "reason": "notification_not_authoritative"}

        assert runtime.request_notification({
            "product_id": "unknown", "version": "1.0.0",
            "installation_id": "install-1", "code": "LICENSE_REQUIRED",
        }) == {"status": "rejected", "reason": "invalid_product_context"}
        assert runtime.request_notification({
            "product_id": "demo", "version": "1.0.0",
            "installation_id": "install-1", "code": "TRIAL_ENDED",
        }) == {"status": "rejected", "reason": "unsupported_notification_code"}


def test_local_notification_route_allows_only_bounded_typed_request():
    seen = []
    with LocalAuthorizationServer(
        lambda _request: {"authorized": False, "reason": "activation_required"},
        notification_request=lambda value: seen.append(value) or {
            "status": "accepted",
            "notification_id": "notice-1",
            "code": value["code"],
        },
    ) as server:
        payload = {
            "product_id": "demo",
            "version": "1.0.0",
            "installation_id": "install-1",
            "code": "LICENSE_REQUIRED",
        }
        request = Request(
            f"{server.url}/v1/notifications/request",
            data=json.dumps(payload).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            result = json.loads(response.read())

        assert result == {
            "capability_id": "bke.notifications.typed",
            "contract_version": 1,
            "status": "accepted",
            "notification_id": "notice-1",
            "code": "LICENSE_REQUIRED",
            "reason": "",
        }
        assert seen == [payload]

        arbitrary_text = Request(
            f"{server.url}/v1/notifications/request",
            data=json.dumps({**payload, "title": "YOUR COMPUTER IS INFECTED"}).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as rejected_text:
            urlopen(arbitrary_text)
        assert rejected_text.value.code == 400

        oversized = Request(
            f"{server.url}/v1/notifications/request",
            data=json.dumps({**payload, "product_id": "p" * 129}).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as rejected_size:
            urlopen(oversized)
        assert rejected_size.value.code == 400

        browser = Request(
            f"{server.url}/v1/notifications/request",
            data=json.dumps(payload).encode(),
            headers={"content-type": "application/json", "origin": "https://attacker.invalid"},
            method="POST",
        )
        with pytest.raises(HTTPError) as rejected_browser:
            urlopen(browser)
        assert rejected_browser.value.code == 403


def test_native_license_center_receives_only_typed_notice_code(tmp_path: Path):
    executable = tmp_path / "bke-license-center.exe"
    executable.touch()
    seen = []
    request = OpenLicenseCenterRequest(
        product_id="demo",
        product_version="1.0.0",
        action=LicenseCenterAction.ACTIVATION_REQUIRED,
        correlation_id="corr-1",
        manifest=_manifest(),
        safe_context={
            "installation_id": "install-1",
            "notification_code": "LICENSE_REQUIRED",
        },
    )
    launcher = NativeLicenseCenterLauncher(
        executable,
        runner=lambda args, **kwargs: seen.append((tuple(args), kwargs)) or SimpleNamespace(returncode=2),
    )

    result = launcher(request)

    assert result.outcome is LicenseCenterOutcome.CANCELLED
    command = seen[0][0]
    assert command[command.index("--notification-code") + 1] == "LICENSE_REQUIRED"
    assert all("commercial license" not in value.lower() for value in command)
    assert seen[0][1] == {"shell": False, "check": False}
