"""Trusted Digital Solutions product-broadcast ingestion for the local Agent inbox."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

import requests

from .notifications import AgentNotificationService, NotificationCode, NotificationSeverity


_REMOTE_CODES = {
    NotificationCode.BETA_ENDED,
    NotificationCode.TRIAL_ENDED,
    NotificationCode.FREE_SUPPORT_ENDED,
    NotificationCode.LICENSE_RENEWAL_REQUIRED,
}


class BroadcastDeliveryMode(StrEnum):
    ONCE = "ONCE"
    EVERY_LAUNCH = "EVERY_LAUNCH"


class ProductBroadcastSyncError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProductBroadcastSyncResult:
    fetched: int
    materialized: int


class ProductBroadcastSynchronizer:
    """Fetch typed broadcast authority; presentation remains entirely Agent-owned."""

    def __init__(
        self,
        notifications: AgentNotificationService,
        *,
        platform_base_url: str,
        session: requests.Session | None = None,
    ) -> None:
        base = platform_base_url.rstrip("/")
        if not base.startswith("https://"):
            raise ValueError("product broadcast authority must use HTTPS")
        self.notifications = notifications
        self.platform_base_url = base
        self.session = session or requests.Session()
        self._delivery_lock = threading.RLock()
        self._every_launch_ids: dict[str, set[str]] = {}

    def is_every_launch(self, product_id: str, notification_id: str) -> bool:
        with self._delivery_lock:
            return notification_id in self._every_launch_ids.get(product_id, set())

    def sync(self, product_id: str, version: str) -> ProductBroadcastSyncResult:
        response = self.session.get(
            f"{self.platform_base_url}/api/licensing-agent/notifications",
            params={"product_id": product_id, "version": version},
            headers={"Accept": "application/json", "User-Agent": "BKE-Licensing-Agent/1"},
            timeout=(3, 5),
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise ProductBroadcastSyncError(
                f"product broadcast authority returned HTTP {response.status_code}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise ProductBroadcastSyncError("product broadcast authority returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ProductBroadcastSyncError("product broadcast response must be an object")
        if payload.get("capabilityId") != "bke.product-broadcasts":
            raise ProductBroadcastSyncError("unexpected product broadcast capability")
        if payload.get("contractVersion") != 1:
            raise ProductBroadcastSyncError("unsupported product broadcast contract")
        if payload.get("source") != "bke-digital-solutions":
            raise ProductBroadcastSyncError("untrusted product broadcast source")
        if payload.get("productId") != product_id or payload.get("version") != version:
            raise ProductBroadcastSyncError("product broadcast context mismatch")
        broadcasts = payload.get("broadcasts")
        if not isinstance(broadcasts, list) or len(broadcasts) > 32:
            raise ProductBroadcastSyncError("invalid product broadcast collection")

        materialized = 0
        seen_codes: set[NotificationCode] = set()
        every_launch_ids: set[str] = set()
        for raw in broadcasts:
            if not isinstance(raw, dict):
                raise ProductBroadcastSyncError("invalid product broadcast item")
            broadcast_id = raw.get("broadcastId")
            if not isinstance(broadcast_id, str):
                raise ProductBroadcastSyncError("product broadcast id is missing")
            try:
                UUID(broadcast_id)
            except ValueError as exc:
                raise ProductBroadcastSyncError("product broadcast id is invalid") from exc
            try:
                code = NotificationCode(str(raw.get("code", "")))
            except ValueError as exc:
                raise ProductBroadcastSyncError("unsupported product broadcast code") from exc
            if code not in _REMOTE_CODES:
                raise ProductBroadcastSyncError("product broadcast code is not remotely materializable")
            if raw.get("audience") != "ALL_ACTIVE_CLIENTS":
                raise ProductBroadcastSyncError("unsupported product broadcast audience")
            priority = raw.get("priority")
            if priority not in {"LOW", "NORMAL", "HIGH", "URGENT"}:
                raise ProductBroadcastSyncError("invalid product broadcast priority")
            try:
                delivery_mode = BroadcastDeliveryMode(str(raw.get("deliveryMode", "ONCE")))
            except ValueError as exc:
                raise ProductBroadcastSyncError("invalid product broadcast delivery mode") from exc
            published_at = raw.get("publishedAt")
            starts_at = raw.get("startsAt")
            ends_at = raw.get("endsAt")
            if not isinstance(published_at, str) or not isinstance(starts_at, str):
                raise ProductBroadcastSyncError("product broadcast timestamps are invalid")
            if ends_at is not None and not isinstance(ends_at, str):
                raise ProductBroadcastSyncError("product broadcast expiry is invalid")

            severity = (
                NotificationSeverity.WARNING
                if priority in {"HIGH", "URGENT"}
                else NotificationSeverity.INFORMATION
            )
            record = self.notifications.ensure_broadcast(
                broadcast_id=broadcast_id,
                product_id=product_id,
                code=code,
                severity=severity,
                expires_at=ends_at,
            )
            if delivery_mode is BroadcastDeliveryMode.EVERY_LAUNCH:
                every_launch_ids.add(record.notification_id)
            seen_codes.add(code)
            materialized += 1

        missing_codes = tuple(
            code.value for code in _REMOTE_CODES if code not in seen_codes
        )
        self.notifications.database.deactivate_notifications_for_codes(product_id, missing_codes)
        with self._delivery_lock:
            self._every_launch_ids[product_id] = every_launch_ids

        return ProductBroadcastSyncResult(fetched=len(broadcasts), materialized=materialized)
