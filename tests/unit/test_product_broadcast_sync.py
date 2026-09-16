from pathlib import Path

import pytest

from bke_licensing_agent.broadcasts import (
    ProductBroadcastSyncError,
    ProductBroadcastSynchronizer,
)
from bke_licensing_agent.notifications import (
    AgentNotificationService,
    NotificationCode,
)
from bke_licensing_agent.storage.database import Database


class _Response:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class _Session:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Response(self.payload)


def _payload(*, broadcast_id="11111111-1111-4111-8111-111111111111", code="FREE_SUPPORT_ENDED"):
    return {
        "capabilityId": "bke.product-broadcasts",
        "contractVersion": 1,
        "source": "bke-digital-solutions",
        "productId": "bke-render-dock",
        "version": "1.0.2",
        "broadcasts": [{
            "broadcastId": broadcast_id,
            "code": code,
            "audience": "ALL_ACTIVE_CLIENTS",
            "priority": "HIGH",
            "minimumVersion": None,
            "maximumVersion": None,
            "publishedAt": "2026-09-17T00:00:00.000Z",
            "startsAt": "2026-09-17T00:00:00.000Z",
            "endsAt": None,
        }],
    }


def test_remote_broadcast_materializes_agent_owned_wording(tmp_path: Path):
    with Database(tmp_path / "agent.db") as database:
        notifications = AgentNotificationService(database)
        session = _Session(_payload())
        sync = ProductBroadcastSynchronizer(
            notifications,
            platform_base_url="https://jl-bke.com",
            session=session,
        )

        result = sync.sync("bke-render-dock", "1.0.2")

        assert result.fetched == result.materialized == 1
        records = notifications.list_for_product("bke-render-dock")
        assert len(records) == 1
        assert records[0].code is NotificationCode.FREE_SUPPORT_ENDED
        presentation = notifications.presentation(records[0].code)
        assert presentation.title == "Free support period ended"
        assert "complimentary support" in presentation.body.lower()
        assert session.calls[0][0] == "https://jl-bke.com/api/licensing-agent/notifications"
        assert session.calls[0][1]["params"] == {
            "product_id": "bke-render-dock",
            "version": "1.0.2",
        }
        assert session.calls[0][1]["allow_redirects"] is False


def test_same_broadcast_preserves_state_but_republish_rearms_unread(tmp_path: Path):
    with Database(tmp_path / "agent.db") as database:
        notifications = AgentNotificationService(database)
        first_session = _Session(_payload())
        first_sync = ProductBroadcastSynchronizer(
            notifications,
            platform_base_url="https://jl-bke.com",
            session=first_session,
        )
        first_sync.sync("bke-render-dock", "1.0.2")
        first = notifications.list_for_product("bke-render-dock")[0]
        assert notifications.dismiss(first.notification_id) is True

        first_sync.sync("bke-render-dock", "1.0.2")
        dismissed = notifications.list_for_product(
            "bke-render-dock", include_dismissed=True
        )[0]
        assert dismissed.notification_id == first.notification_id
        assert dismissed.state == "dismissed"

        second_sync = ProductBroadcastSynchronizer(
            notifications,
            platform_base_url="https://jl-bke.com",
            session=_Session(_payload(
                broadcast_id="22222222-2222-4222-8222-222222222222"
            )),
        )
        second_sync.sync("bke-render-dock", "1.0.2")
        current = notifications.list_for_product("bke-render-dock")[0]
        assert current.notification_id != first.notification_id
        assert current.state == "unread"


def test_remote_authority_cannot_invent_notification_code(tmp_path: Path):
    with Database(tmp_path / "agent.db") as database:
        sync = ProductBroadcastSynchronizer(
            AgentNotificationService(database),
            platform_base_url="https://jl-bke.com",
            session=_Session(_payload(code="REMOTE_TEXT_MESSAGE")),
        )
        with pytest.raises(ProductBroadcastSyncError, match="unsupported product broadcast code"):
            sync.sync("bke-render-dock", "1.0.2")
