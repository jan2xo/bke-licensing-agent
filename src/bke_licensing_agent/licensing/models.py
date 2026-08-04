from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

class LicenseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class LicensePolicy(LicenseModel):
    can_activate: bool = False
    maximum_version: str | None = None

class LicenseSummary(LicenseModel):
    license_id: str
    product_id: str
    status: Literal["active", "inactive", "pending", "expired", "suspended", "revoked", "device_limit_reached", "product_unavailable", "version_not_entitled", "authentication_required", "unknown"]

class LicenseListResponse(LicenseModel):
    licenses: list[LicenseSummary]

class LicenseEntitlement(LicenseSummary):
    policy: LicensePolicy = Field(default_factory=LicensePolicy)
    expires_at: datetime | None = None

class DeviceMetadata(LicenseModel):
    installation_id: str
    device_fingerprint: str
    fingerprint_schema_version: str
    operating_system: str
    os_version: str
    architecture: str
    device_name: str | None = None
    agent_version: str

class DeviceRegistrationRequest(LicenseModel):
    metadata: DeviceMetadata

class DeviceRegistrationResponse(LicenseModel):
    device_id: str
    status: Literal["authorized", "pending", "denied"]

class ActivationRequest(LicenseModel):
    product_id: str
    license_id: str
    device_id: str
    installed_version: str

class ActivationResponse(LicenseModel):
    activation_id: str
    license_id: str
    product_id: str
    device_id: str
    status: Literal["active", "expired", "suspended", "revoked", "device_limit_reached", "version_not_entitled", "unknown"]
    policy: dict[str, Any] = Field(default_factory=dict)

class ActivationVerificationRequest(LicenseModel):
    activation_id: str
    product_id: str
    device_id: str

class ActivationVerificationResponse(LicenseModel):
    valid: bool
    status: Literal["active", "expired", "suspended", "revoked", "unknown"]
    activation_id: str

class DeactivationRequest(LicenseModel):
    activation_id: str
    device_id: str

class DeactivationResponse(LicenseModel):
    success: bool

class ActivationState(LicenseModel):
    state: str
    activation_id: str | None = None
