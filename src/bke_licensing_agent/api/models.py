from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthResponse(ApiModel):
    status: Literal["ok", "degraded"]
    service: str
    version: str


class ProductResponse(ApiModel):
    product_id: str
    display_name: str
    active: bool
    latest_version: str | None = None


class LicenseStatusResponse(ApiModel):
    status: Literal["active", "expired", "suspended", "revoked", "unavailable"]
    license_id: str
    product_id: str
    device_id: str | None = None
    policy: dict[str, Any] = Field(default_factory=dict)


class DeviceRegistrationRequest(ApiModel):
    device_name: str = Field(min_length=1)
    device_fingerprint: str = Field(min_length=1)


class DeviceRegistrationResponse(ApiModel):
    device_id: str
    status: Literal["authorized", "pending", "denied"]


class LicenseVerificationRequest(ApiModel):
    product_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    installed_version: str = Field(min_length=1)


class LicenseVerificationResponse(ApiModel):
    valid: bool
    status: Literal["active", "expired", "suspended", "revoked", "unavailable"]
    license_id: str | None = None
    policy: dict[str, Any] = Field(default_factory=dict)


class PlatformLeaseActivationRequest(ApiModel):
    licenseKey: str = Field(min_length=1)
    installationId: str = Field(min_length=32, max_length=256)
    deviceId: str = Field(min_length=16, max_length=256)
    operationId: str = Field(min_length=8, max_length=128)
    productVersion: str = Field(min_length=1)
    label: str | None = None
    operatingSystem: str | None = None
    architecture: str | None = None


class PlatformLeaseResponse(ApiModel):
    lease: dict[str, Any]


class UpdateDiscoveryRequest(ApiModel):
    lease: dict[str, Any]
    product_id: str = Field(min_length=1)
    current_version: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    channel: Literal["stable", "lts"] = "stable"


class UpdateDiscoveryResponse(ApiModel):
    status: Literal["up_to_date", "update_available"]
    policy: dict[str, Any] | None = None
    download_url: str | None = None
