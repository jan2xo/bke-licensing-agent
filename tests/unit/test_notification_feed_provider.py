import json
from pathlib import Path
from urllib.request import Request, urlopen

from bke_licensing_agent.manifest.validator import validate_manifest
from bke_licensing_agent.notification_local_api import NotificationLocalAuthorizationServer
from bke_licensing_agent.notification_runtime import NotificationEnabledAgentRuntime
from bke_licensing_agent.notifications import AgentNotificationService, NotificationCode
from bke_licensing_agent.storage.database import Database


def _manifest():
    return validate_manifest({
        "schemaVersion": 1,
        "productId": "bke-render-dock",
        "displayName": "Render Dock",
        "version": "1.0.2",
        "entryPoint": "BKE_RENDER_DOCK.exe",
        "updateChannel": "stable",
        "minimumAgentVersion": "1.0.0",
        "platform": "windows",
        "architecture": "x64",
    })


def _runtime(database: Database) -> NotificationEnabledAgentRuntime:
    runtime = object.__new__(NotificationEnabledAgentRuntime)
    runtime.database = database
    runtime.notifications = AgentNotificationService(database)
    runtime._validated_product = lambda product_id, version: (
        _manifest() if (product_id, version) == ("bke-render-dock", "1.0.2") else None
    )
    return runtime


def test_notification_inbox_feed_read_dismiss_and_unread_count(tmp_path: Path):
    with Database(tmp_path / "agent.db") as database:
        runtime = _runtime(database)
        notice = runtime.notifications.ensure("bke-render-dock", NotificationCode.LICENSE_REQUIRED)
        context = {"product_id": "bke-render-dock", "version": "1.0.2"}

        unread = runtime.notification_unread_count(context)
        assert unread == {"status": "Succeeded", "count": 1, "error": None}

        feed = runtime.notification_feed({**context, "limit": 50, "include_dismissed": False})
        assert feed["status"] == "Succeeded"
        assert len(feed["items"]) == 1
        item = feed["items"][0]
        assert item["id"] == notice.notification_id
        assert item["title"] == "License required"
        assert "commercial license" in item["body"].lower()
        assert item["state"] == "Unread"
        assert item["category"] == "Licensing"
        assert item["severity"] == "Warning"
        assert item["actions"] == []

        assert runtime.notification_mark_read({**context, "notification_id": notice.notification_id}) == {
            "status": "Succeeded", "error": None,
        }
        assert runtime.notification_unread_count(context)["count"] == 0
        assert runtime.notification_feed({**context, "limit": 50, "include_dismissed": False})["items"][0]["state"] == "Read"

        assert runtime.notification_dismiss({**context, "notification_id": notice.notification_id}) == {
            "status": "Succeeded", "error": None,
        }
        assert runtime.notification_feed({**context, "limit": 50, "include_dismissed": False})["items"] == []
        dismissed = runtime.notification_feed({**context, "limit": 50, "include_dismissed": True})["items"]
        assert len(dismissed) == 1
        assert dismissed[0]["state"] == "Dismissed"


def test_notification_inbox_lifecycle_is_product_scoped(tmp_path: Path):
    with Database(tmp_path / "agent.db") as database:
        runtime = _runtime(database)
        notice = runtime.notifications.ensure("bke-render-dock", NotificationCode.LICENSE_REQUIRED)
        wrong_context = {"product_id": "other-product", "version": "1.0.2", "notification_id": notice.notification_id}

        result = runtime.notification_dismiss(wrong_context)
        assert result["status"] == "Failed"
        assert result["error"]["code"] == "InvalidRequest"
        assert runtime.notifications.list_for_product("bke-render-dock")[0].state == "unread"


def test_notification_inbox_http_contract_is_product_read_only():
    feed_requests = []
    dismiss_requests = []
    with NotificationLocalAuthorizationServer(
        lambda _request: {"authorized": False, "reason": "activation_required"},
        notification_feed=lambda value: feed_requests.append(value) or {
            "status": "Succeeded", "items": [], "error": None,
        },
        notification_mark_read=lambda _value: {"status": "Succeeded", "error": None},
        notification_dismiss=lambda value: dismiss_requests.append(value) or {
            "status": "Succeeded", "error": None,
        },
        notification_unread_count=lambda _value: {"status": "Succeeded", "count": 0, "error": None},
    ) as server:
        feed_body = {
            "product_id": "bke-render-dock",
            "version": "1.0.2",
            "limit": 25,
            "include_dismissed": False,
        }
        request = Request(
            f"{server.url}/v1/notifications/feed",
            data=json.dumps(feed_body).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            result = json.loads(response.read())
        assert result == {
            "capability_id": "bke.notifications",
            "contract_version": 1,
            "status": "Succeeded",
            "items": [],
            "error": None,
        }
        assert feed_requests == [feed_body]

        dismiss_body = {
            "product_id": "bke-render-dock",
            "version": "1.0.2",
            "notification_id": "notice-1",
        }
        request = Request(
            f"{server.url}/v1/notifications/dismiss",
            data=json.dumps(dismiss_body).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            result = json.loads(response.read())
        assert result["capability_id"] == "bke.notifications"
        assert result["contract_version"] == 1
        assert result["status"] == "Succeeded"
        assert dismiss_requests == [dismiss_body]
