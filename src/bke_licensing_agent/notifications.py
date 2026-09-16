"""Agent-owned typed notification persistence and presentation policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import NAMESPACE_URL, uuid5

from .storage.database import Database


class NotificationCode(StrEnum):
    """Codes the shipping Agent can safely materialize from authoritative state."""

    LICENSE_REQUIRED = "LICENSE_REQUIRED"
    AGENT_UPDATE_AVAILABLE = "AGENT_UPDATE_AVAILABLE"
    BETA_ENDED = "BETA_ENDED"
    TRIAL_ENDED = "TRIAL_ENDED"
    FREE_SUPPORT_ENDED = "FREE_SUPPORT_ENDED"
    LICENSE_RENEWAL_REQUIRED = "LICENSE_RENEWAL_REQUIRED"


class NotificationSeverity(StrEnum):
    INFORMATION = "information"
    WARNING = "warning"


@dataclass(frozen=True)
class NotificationRecord:
    notification_id: str
    product_id: str
    code: NotificationCode
    severity: NotificationSeverity
    state: str
    created_at: str
    expires_at: str | None = None


@dataclass(frozen=True)
class NotificationPresentation:
    title: str
    body: str


_PRESENTATION = {
    NotificationCode.LICENSE_REQUIRED: NotificationPresentation(
        title="License required",
        body=(
            "This installation is not currently authorized. "
            "A commercial license is required to continue."
        ),
    ),
    NotificationCode.AGENT_UPDATE_AVAILABLE: NotificationPresentation(
        title="BKE Licensing Agent update",
        body="A newer BKE Licensing Agent release is available.",
    ),
    NotificationCode.BETA_ENDED: NotificationPresentation(
        title="Beta period ended",
        body=(
            "The free beta period for this product has ended. "
            "Commercial licensing now applies to continued use."
        ),
    ),
    NotificationCode.TRIAL_ENDED: NotificationPresentation(
        title="Trial period ended",
        body=(
            "The trial period for this product has ended. "
            "Purchase or activate a commercial license to continue using the software."
        ),
    ),
    NotificationCode.FREE_SUPPORT_ENDED: NotificationPresentation(
        title="Free support period ended",
        body=(
            "The complimentary support period for this product has ended. "
            "Continued support is available under the applicable commercial support terms."
        ),
    ),
    NotificationCode.LICENSE_RENEWAL_REQUIRED: NotificationPresentation(
        title="License renewal required",
        body=(
            "The current commercial license requires renewal. "
            "Renew the license to continue receiving licensed access and services."
        ),
    ),
}

_CATEGORY = {
    NotificationCode.LICENSE_REQUIRED: "Licensing",
    NotificationCode.AGENT_UPDATE_AVAILABLE: "Update",
    NotificationCode.BETA_ENDED: "Product",
    NotificationCode.TRIAL_ENDED: "Product",
    NotificationCode.FREE_SUPPORT_ENDED: "Product",
    NotificationCode.LICENSE_RENEWAL_REQUIRED: "Licensing",
}


class AgentNotificationService:
    """Persist typed notices; caller-supplied customer-facing text is never stored."""

    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def presentation(code: NotificationCode | str) -> NotificationPresentation:
        return _PRESENTATION[NotificationCode(code)]

    @staticmethod
    def category(code: NotificationCode | str) -> str:
        return _CATEGORY[NotificationCode(code)]

    def ensure(
        self,
        product_id: str,
        code: NotificationCode,
        *,
        severity: NotificationSeverity = NotificationSeverity.WARNING,
        expires_at: str | None = None,
    ) -> NotificationRecord:
        notification_id = str(uuid5(NAMESPACE_URL, f"bke-notification:{product_id}:{code.value}"))
        row = self.database.ensure_notification(
            notification_id=notification_id,
            product_id=product_id,
            code=code.value,
            severity=severity.value,
            expires_at=expires_at,
        )
        return self._record(row)

    def ensure_broadcast(
        self,
        *,
        broadcast_id: str,
        product_id: str,
        code: NotificationCode,
        severity: NotificationSeverity,
        expires_at: str | None,
    ) -> NotificationRecord:
        """Materialize one remote campaign and re-arm only when its broadcastId changes."""
        notification_id = str(uuid5(NAMESPACE_URL, f"bke-product-broadcast:{broadcast_id}"))
        row = self.database.ensure_notification(
            notification_id=notification_id,
            product_id=product_id,
            code=code.value,
            severity=severity.value,
            expires_at=expires_at,
            replace_campaign=True,
        )
        return self._record(row)

    def list_for_product(
        self, product_id: str, *, include_dismissed: bool = False, limit: int = 50
    ) -> tuple[NotificationRecord, ...]:
        return tuple(
            self._record(row)
            for row in self.database.list_notifications(
                product_id, include_dismissed=include_dismissed, limit=limit
            )
        )

    def dismiss(self, notification_id: str) -> bool:
        return self.database.dismiss_notification(notification_id)

    @staticmethod
    def _record(row: dict[str, object]) -> NotificationRecord:
        return NotificationRecord(
            notification_id=str(row["id"]),
            product_id=str(row["product_id"]),
            code=NotificationCode(str(row["code"])),
            severity=NotificationSeverity(str(row["severity"])),
            state=str(row["state"]),
            created_at=str(row["created_at"]),
            expires_at=str(row["expires_at"]) if row.get("expires_at") is not None else None,
        )
