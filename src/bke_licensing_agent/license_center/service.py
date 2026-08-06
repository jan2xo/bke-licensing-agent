"""Product-agnostic License Center invocation boundary."""

from collections.abc import Callable
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..manifest.models import Manifest
from .controller import Screen


class LicenseCenterAction(StrEnum):
    ACTIVATION_REQUIRED = "activation_required"
    ADD_LICENSE = "add_license"
    SELECT_LICENSE = "select_license"
    ACTIVATE_LICENSE = "activate_license"
    VIEW_LICENSE = "view_license"
    VIEW_LICENSES = "view_licenses"
    REMOVE_LICENSE = "remove_license"
    REFRESH_LICENSE = "refresh_license"
    DEACTIVATE_DEVICE = "deactivate_device"


class LicenseCenterOutcome(StrEnum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    AGENT_UNAVAILABLE = "agent_unavailable"
    INVALID_PRODUCT_CONTEXT = "invalid_product_context"
    INCOMPATIBLE_PRODUCT_VERSION = "incompatible_product_version"
    ACTIVATION_FAILED = "activation_failed"
    AUTHORIZATION_REFRESHED = "authorization_refreshed"


class OpenLicenseCenterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str = Field(min_length=1)
    product_version: str = Field(min_length=1)
    action: LicenseCenterAction
    correlation_id: str = Field(min_length=1)
    manifest: Manifest
    requesting_process_id: int | None = Field(default=None, gt=0)
    return_to_product: bool = True
    safe_context: dict[str, str] | None = None

    @field_validator("correlation_id")
    @classmethod
    def validate_correlation_id(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("correlation_id contains control characters")
        return value


class OpenLicenseCenterResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: LicenseCenterOutcome
    reason: str = ""
    product_id: str
    correlation_id: str
    authorization_changed: bool = False
    authorization_summary: dict[str, str] | None = None


class LicenseCenterService:
    """Validates product context and delegates UI work to the shared center."""

    def __init__(self, launcher: Callable[[OpenLicenseCenterRequest], OpenLicenseCenterResult] | None = None):
        self.launcher = launcher

    def open_license_center(self, request: OpenLicenseCenterRequest) -> OpenLicenseCenterResult:
        if not request.manifest.is_validated:
            return self._invalid(request, "manifest provenance is not validated")
        if request.product_id != request.manifest.productId:
            return self._invalid(request, "product context does not match manifest")
        if request.product_version != request.manifest.version:
            return OpenLicenseCenterResult(
                outcome=LicenseCenterOutcome.INCOMPATIBLE_PRODUCT_VERSION,
                reason="product version does not match manifest",
                product_id=request.product_id,
                correlation_id=request.correlation_id,
            )
        if self.launcher is None:
            return OpenLicenseCenterResult(
                outcome=LicenseCenterOutcome.AGENT_UNAVAILABLE,
                reason="License Center launcher is unavailable",
                product_id=request.product_id,
                correlation_id=request.correlation_id,
            )
        try:
            result = OpenLicenseCenterResult.model_validate(self.launcher(request))
        except Exception:
            return OpenLicenseCenterResult(
                outcome=LicenseCenterOutcome.FAILED,
                reason="License Center invocation failed",
                product_id=request.product_id,
                correlation_id=request.correlation_id,
            )
        return result

    def dispatch_action(self, request: OpenLicenseCenterRequest, controller: Any,
                        product: Any, *, license_id: str | None = None) -> OpenLicenseCenterResult:
        """Dispatch a validated request through the Agent-owned controller."""
        try:
            action = request.action
            controller.connect()
            controller.select_product(product)
            if action in {LicenseCenterAction.ACTIVATION_REQUIRED, LicenseCenterAction.ADD_LICENSE,
                           LicenseCenterAction.ACTIVATE_LICENSE}:
                state = controller.activate()
            elif action is LicenseCenterAction.SELECT_LICENSE:
                if license_id is None or not hasattr(controller.agent, "select_license"):
                    return self._invalid(request, "license selection requires Agent resolution")
                decision = controller.agent.select_license(product, license_id)
                state = controller.state
                state = state.__class__(screen=Screen.STATUS, connected=True, authenticated=True,
                    products=state.products, selected_product=product, status=decision,
                    return_to_product=True)
            elif action is LicenseCenterAction.VIEW_LICENSES:
                summaries = controller.agent.list_licenses(product)
                return OpenLicenseCenterResult(outcome=LicenseCenterOutcome.COMPLETED,
                    product_id=request.product_id, correlation_id=request.correlation_id,
                    authorization_summary={"licenses": str(len(summaries))})
            elif action is LicenseCenterAction.REMOVE_LICENSE:
                if license_id is None:
                    return self._invalid(request, "license removal requires Agent resolution")
                controller.agent.remove_license(product, license_id)
                state = controller.state
            elif action is LicenseCenterAction.REFRESH_LICENSE:
                state = controller._status()
            elif action is LicenseCenterAction.DEACTIVATE_DEVICE:
                state = controller.deactivate()
            else:
                return self._invalid(request, "unknown License Center action")
            if getattr(state, "screen", None) is Screen.STATUS:
                return OpenLicenseCenterResult(outcome=LicenseCenterOutcome.AUTHORIZATION_REFRESHED,
                    product_id=request.product_id, correlation_id=request.correlation_id,
                    authorization_changed=True)
            return OpenLicenseCenterResult(outcome=LicenseCenterOutcome.FAILED,
                reason=getattr(state, "error", None) or "License Center action failed",
                product_id=request.product_id, correlation_id=request.correlation_id)
        except Exception:
            return OpenLicenseCenterResult(outcome=LicenseCenterOutcome.FAILED,
                reason="License Center action failed", product_id=request.product_id,
                correlation_id=request.correlation_id)

    @staticmethod
    def _invalid(request: OpenLicenseCenterRequest, reason: str) -> OpenLicenseCenterResult:
        return OpenLicenseCenterResult(
            outcome=LicenseCenterOutcome.INVALID_PRODUCT_CONTEXT,
            reason=reason,
            product_id=request.product_id,
            correlation_id=request.correlation_id,
        )
