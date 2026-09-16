"""Read-only notification inbox routes layered on the Agent loopback API."""

from __future__ import annotations

import json
from typing import Callable

from .local_api import LocalAuthorizationServer


NOTIFICATION_INBOX_CAPABILITY_ID = "bke.notifications"
NOTIFICATION_INBOX_CONTRACT_VERSION = 1


class NotificationLocalAuthorizationServer(LocalAuthorizationServer):
    """Extend the existing loopback server with least-privilege inbox operations."""

    def __init__(
        self,
        *args,
        notification_feed: Callable[[dict[str, object]], dict[str, object]] | None = None,
        notification_mark_read: Callable[[dict[str, object]], dict[str, object]] | None = None,
        notification_dismiss: Callable[[dict[str, object]], dict[str, object]] | None = None,
        notification_unread_count: Callable[[dict[str, object]], dict[str, object]] | None = None,
        **kwargs,
    ):
        self._notification_feed = notification_feed
        self._notification_mark_read = notification_mark_read
        self._notification_dismiss = notification_dismiss
        self._notification_unread_count = notification_unread_count
        super().__init__(*args, **kwargs)

    def _handler(self):
        base_handler = super()._handler()
        notification_feed = self._notification_feed
        notification_mark_read = self._notification_mark_read
        notification_dismiss = self._notification_dismiss
        notification_unread_count = self._notification_unread_count

        class Handler(base_handler):
            _INBOX_PATHS = {
                "/v1/notifications/feed",
                "/v1/notifications/mark-read",
                "/v1/notifications/dismiss",
                "/v1/notifications/unread-count",
            }

            def _inbox_failure(
                self,
                http_status: int,
                code: str,
                message: str,
                *,
                retryable: bool = False,
            ) -> None:
                self._json(http_status, {
                    "capability_id": NOTIFICATION_INBOX_CAPABILITY_ID,
                    "contract_version": NOTIFICATION_INBOX_CONTRACT_VERSION,
                    "status": "Failed",
                    "error": {
                        "code": code,
                        "message": message,
                        "retryable": retryable,
                    },
                })

            @staticmethod
            def _valid_context(body: dict[str, object]) -> bool:
                product_id = body.get("product_id")
                version = body.get("version")
                installation_id = body.get("installation_id")
                return (
                    isinstance(product_id, str)
                    and bool(product_id.strip())
                    and len(product_id) <= 128
                    and isinstance(version, str)
                    and bool(version.strip())
                    and len(version) <= 64
                    and isinstance(installation_id, str)
                    and bool(installation_id.strip())
                    and len(installation_id) <= 256
                )

            def do_POST(self):  # noqa: N802
                if self.path not in self._INBOX_PATHS:
                    return super().do_POST()

                try:
                    if self.headers.get("origin") is not None:
                        self._inbox_failure(403, "Rejected", "Browser-origin requests are not allowed.")
                        return
                    if self.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                        self._inbox_failure(415, "InvalidRequest", "Notification requests must use application/json.")
                        return

                    raw_body = self._read_request_body()
                    if raw_body is None:
                        return
                    body = json.loads(raw_body)
                    if not isinstance(body, dict) or not self._valid_context(body):
                        self._inbox_failure(400, "InvalidRequest", "Invalid notification product context.")
                        return

                    if self.path == "/v1/notifications/feed":
                        if notification_feed is None:
                            self._inbox_failure(503, "ProviderUnavailable", "The notification provider is unavailable.", retryable=True)
                            return
                        if set(body) != {"product_id", "version", "installation_id", "limit", "include_dismissed"}:
                            self._inbox_failure(400, "InvalidRequest", "Invalid notification feed request.")
                            return
                        limit = body.get("limit")
                        include_dismissed = body.get("include_dismissed")
                        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > 200 or not isinstance(include_dismissed, bool):
                            self._inbox_failure(400, "InvalidRequest", "Invalid notification feed query.")
                            return
                        result = notification_feed(body)

                    elif self.path == "/v1/notifications/unread-count":
                        if notification_unread_count is None:
                            self._inbox_failure(503, "ProviderUnavailable", "The notification provider is unavailable.", retryable=True)
                            return
                        if set(body) != {"product_id", "version", "installation_id"}:
                            self._inbox_failure(400, "InvalidRequest", "Invalid unread-count request.")
                            return
                        result = notification_unread_count(body)

                    else:
                        callback = notification_mark_read if self.path.endswith("mark-read") else notification_dismiss
                        if callback is None:
                            self._inbox_failure(503, "ProviderUnavailable", "The notification provider is unavailable.", retryable=True)
                            return
                        if set(body) != {"product_id", "version", "installation_id", "notification_id"}:
                            self._inbox_failure(400, "InvalidRequest", "Invalid notification lifecycle request.")
                            return
                        notification_id = body.get("notification_id")
                        if not isinstance(notification_id, str) or not notification_id.strip() or len(notification_id) > 128:
                            self._inbox_failure(400, "InvalidRequest", "Invalid notification identifier.")
                            return
                        result = callback(body)

                    response = {
                        "capability_id": NOTIFICATION_INBOX_CAPABILITY_ID,
                        "contract_version": NOTIFICATION_INBOX_CONTRACT_VERSION,
                        **result,
                    }
                    self._json(200, response)
                except (ValueError, TypeError, json.JSONDecodeError):
                    self._inbox_failure(400, "InvalidRequest", "Invalid notification request.")
                except Exception:
                    self._inbox_failure(500, "Unknown", "The notification provider failed.", retryable=True)

        return Handler
