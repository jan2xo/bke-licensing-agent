"""Notification-enabled installed Agent runtime composition."""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from .broadcasts import ProductBroadcastSynchronizer
from .config import get_platform_base_url
from .notification_local_api import NotificationLocalAuthorizationServer
from .notifications import AgentNotificationService, NotificationCode
from .runtime import InstalledAgentRuntime


class NotificationEnabledAgentRuntime(InstalledAgentRuntime):
    """Expose Agent-owned persisted notices through a least-privilege inbox contract."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.product_broadcasts = ProductBroadcastSynchronizer(
            self.notifications,
            platform_base_url=get_platform_base_url(),
        )

    @staticmethod
    def _error(code: str, message: str, *, retryable: bool = False) -> dict[str, object]:
        return {
            "status": "Failed",
            "error": {"code": code, "message": message, "retryable": retryable},
        }

    def _valid_product_context(self, request: dict[str, object]) -> bool:
        product_id = request.get("product_id")
        version = request.get("version")
        installation_id = request.get("installation_id")
        return (
            isinstance(product_id, str)
            and isinstance(version, str)
            and isinstance(installation_id, str)
            and bool(installation_id)
            and self._validated_product(product_id, version) is not None
        )

    @staticmethod
    def _not_expired(expires_at: str | None) -> bool:
        if expires_at is None:
            return True
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            return expiry > datetime.now(timezone.utc)
        except ValueError:
            return False

    def _sync_product_broadcasts(self, request: dict[str, object]) -> None:
        """Best-effort remote sync; notification transport must never become a startup authority."""
        try:
            self.product_broadcasts.sync(
                str(request["product_id"]),
                str(request["version"]),
            )
        except Exception:
            return

    def _visible_notifications(
        self,
        request: dict[str, object],
        *,
        include_dismissed: bool,
        limit: int,
    ):
        product_id = str(request["product_id"])
        version = str(request["version"])
        installation_id = str(request["installation_id"])
        records = self.notifications.list_for_product(
            product_id,
            include_dismissed=include_dismissed,
            limit=limit,
        )
        authorization: dict[str, object] | None = None
        visible = []
        for record in records:
            if not self._not_expired(record.expires_at):
                continue
            if record.code is NotificationCode.LICENSE_REQUIRED:
                if authorization is None:
                    authorization = self.authorize({
                        "product_id": product_id,
                        "version": version,
                        "installation_id": installation_id,
                    })
                if authorization.get("authorized") is True or authorization.get("reason") != "activation_required":
                    continue
            visible.append(record)
        return visible

    def notification_feed(self, request: dict[str, object]) -> dict[str, object]:
        if not self._valid_product_context(request):
            return self._error("InvalidRequest", "The notification product context is invalid.")

        self._sync_product_broadcasts(request)
        limit = int(request["limit"])
        include_dismissed = bool(request["include_dismissed"])
        records = self._visible_notifications(
            request,
            include_dismissed=include_dismissed,
            limit=limit,
        )

        items: list[dict[str, object]] = []
        state_names = {"unread": "Unread", "read": "Read", "dismissed": "Dismissed"}
        severity_names = {"information": "Information", "warning": "Warning"}
        for record in records:
            presentation = AgentNotificationService.presentation(record.code)
            items.append({
                "id": record.notification_id,
                "source": "bke-licensing-agent",
                "title": presentation.title,
                "body": presentation.body,
                "category": AgentNotificationService.category(record.code),
                "severity": severity_names.get(record.severity.value, "Information"),
                "created_at": record.created_at,
                "expires_at": record.expires_at,
                "state": state_names.get(record.state, "Unread"),
                "actions": [],
            })

        return {"status": "Succeeded", "items": items, "error": None}

    def _notification_exists(self, product_id: str, notification_id: str) -> str | None:
        with self.database._lock:  # Agent-owned DB lock; lifecycle remains inside the runtime boundary.
            row = self.database.connection.execute(
                "SELECT state FROM notifications WHERE id=? AND product_id=?",
                (notification_id, product_id),
            ).fetchone()
        return str(row["state"]) if row is not None else None

    def notification_mark_read(self, request: dict[str, object]) -> dict[str, object]:
        if not self._valid_product_context(request):
            return self._error("InvalidRequest", "The notification product context is invalid.")
        product_id = str(request["product_id"])
        notification_id = str(request["notification_id"])
        state = self._notification_exists(product_id, notification_id)
        if state is None:
            return {"status": "NotFound", "error": None}
        if state == "unread":
            with self.database._lock, self.database.connection:
                self.database.connection.execute(
                    "UPDATE notifications SET state='read' WHERE id=? AND product_id=? AND state='unread'",
                    (notification_id, product_id),
                )
        return {"status": "Succeeded", "error": None}

    def notification_dismiss(self, request: dict[str, object]) -> dict[str, object]:
        if not self._valid_product_context(request):
            return self._error("InvalidRequest", "The notification product context is invalid.")
        product_id = str(request["product_id"])
        notification_id = str(request["notification_id"])
        state = self._notification_exists(product_id, notification_id)
        if state is None:
            return {"status": "NotFound", "error": None}
        if state != "dismissed":
            dismissed_at = datetime.now(timezone.utc).isoformat()
            with self.database._lock, self.database.connection:
                self.database.connection.execute(
                    "UPDATE notifications SET state='dismissed', dismissed_at=? WHERE id=? AND product_id=?",
                    (dismissed_at, notification_id, product_id),
                )
        return {"status": "Succeeded", "error": None}

    def notification_unread_count(self, request: dict[str, object]) -> dict[str, object]:
        if not self._valid_product_context(request):
            return self._error("InvalidRequest", "The notification product context is invalid.")
        self._sync_product_broadcasts(request)
        records = self._visible_notifications(request, include_dismissed=False, limit=200)
        count = sum(1 for record in records if record.state == "unread")
        return {"status": "Succeeded", "count": count, "error": None}

    def serve_forever(self) -> None:
        if self._module_server is not None:
            self._module_server.start()
        self._update_stop.clear()
        self._update_thread = threading.Thread(
            target=self._refresh_updates_background,
            daemon=True,
            name="bke-update-refresh",
        )
        self._update_thread.start()
        with NotificationLocalAuthorizationServer(
            self.authorize,
            self.activate,
            self.open_license_center,
            notification_request=self.request_notification,
            notification_feed=self.notification_feed,
            notification_mark_read=self.notification_mark_read,
            notification_dismiss=self.notification_dismiss,
            notification_unread_count=self.notification_unread_count,
            update_check=self.check_update_capability,
            open_update_center=self.open_update_center,
            port=self.port,
        ) as server:
            self._server = server
            try:
                while not self._update_stop.wait(1):
                    pass
            except KeyboardInterrupt:
                self._update_stop.set()
                return
            finally:
                self._update_stop.set()
                self._server = None
                if self._module_server is not None:
                    self._module_server.stop()
