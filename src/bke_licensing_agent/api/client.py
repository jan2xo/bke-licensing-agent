import json
import logging
import time
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

import requests
from pydantic import BaseModel, ValidationError

from .config import ApiConfig
from .endpoints import DEVICES, HEALTH, LICENSE_STATUS, LICENSE_VERIFY, PRODUCT, LOGIN, REFRESH, LOGOUT, SESSION, LICENSES, ENTITLEMENT, DEVICE_STATUS, ACTIVATE, VERIFY_ACTIVATION, DEACTIVATE
from .errors import (
    ApiError, AuthenticationExpiredError, AuthenticationRequiredError,
    AuthorizationDeniedError, ConflictError, ConnectionTimeoutError,
    InvalidServerResponseError, NetworkUnavailableError, RateLimitExceededError,
    RequestTimeoutError, ResourceNotFoundError, ServerUnavailableError,
    TlsFailureError, UnknownApiError, UnsupportedClientVersionError,
)
from .models import (
    DeviceRegistrationRequest, DeviceRegistrationResponse, HealthResponse,
    LicenseStatusResponse, LicenseVerificationRequest, LicenseVerificationResponse,
    ProductResponse,
)
from ..auth.models import (AuthenticationState, LoginRequest, LoginResponse, LogoutRequest,
    LogoutResponse, RefreshRequest, RefreshResponse, SessionInfo, ValidationResponse)
from ..licensing.models import (ActivationRequest, ActivationResponse, ActivationVerificationRequest, ActivationVerificationResponse, DeactivationRequest, DeactivationResponse, LicenseEntitlement, LicenseListResponse, LicenseSummary, DeviceRegistrationRequest as TypedDeviceRegistrationRequest, DeviceRegistrationResponse as TypedDeviceRegistrationResponse)

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


class LicensingPlatformClient:
    def __init__(self, config: ApiConfig, session: requests.Session | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.config = config
        self.session = session or requests.Session()
        self.sleep = sleep

    def health(self) -> HealthResponse:
        return self._request("GET", HEALTH, HealthResponse)

    def product(self, product_id: str) -> ProductResponse:
        return self._request("GET", PRODUCT.format(product_id=product_id), ProductResponse)

    def license_status(self, license_id: str) -> LicenseStatusResponse:
        return self._request("GET", LICENSE_STATUS.format(license_id=license_id), LicenseStatusResponse)

    def register_device(self, request: DeviceRegistrationRequest) -> DeviceRegistrationResponse:
        return self._request("POST", DEVICES, DeviceRegistrationResponse, request.model_dump(), idempotent=False)

    def verify_license(self, request: LicenseVerificationRequest) -> LicenseVerificationResponse:
        return self._request("POST", LICENSE_VERIFY, LicenseVerificationResponse, request.model_dump(), idempotent=False)

    def login(self, request: LoginRequest) -> LoginResponse:
        return self._request("POST", LOGIN, LoginResponse, request.model_dump(), idempotent=False)

    def refresh_session(self, request: RefreshRequest) -> RefreshResponse:
        return self._request("POST", REFRESH, RefreshResponse, request.model_dump(), idempotent=False)

    def logout(self, request: LogoutRequest, access_token: str | None = None) -> LogoutResponse:
        return self._request("POST", LOGOUT, LogoutResponse, request.model_dump(), idempotent=False, access_token=access_token)

    def validate_session(self, access_token: str) -> ValidationResponse:
        return self._request("GET", SESSION, ValidationResponse, idempotent=True, access_token=access_token)

    def list_licenses(self, access_token: str) -> list[LicenseSummary]:
        return self._request("GET", LICENSES, LicenseListResponse, access_token=access_token).licenses

    def entitlement(self, product_id: str, access_token: str) -> LicenseEntitlement:
        return self._request("GET", ENTITLEMENT.format(product_id=product_id), LicenseEntitlement, access_token=access_token)

    def register_typed_device(self, request: TypedDeviceRegistrationRequest, access_token: str) -> TypedDeviceRegistrationResponse:
        return self._request("POST", DEVICES, TypedDeviceRegistrationResponse, request.model_dump(), idempotent=False, access_token=access_token)

    def device_status(self, device_id: str, access_token: str) -> TypedDeviceRegistrationResponse:
        return self._request("GET", DEVICE_STATUS.format(device_id=device_id), TypedDeviceRegistrationResponse, access_token=access_token)

    def activate(self, request: ActivationRequest, access_token: str) -> ActivationResponse:
        return self._request("POST", ACTIVATE, ActivationResponse, request.model_dump(), idempotent=False, access_token=access_token)

    def verify_activation(self, request: ActivationVerificationRequest, access_token: str) -> ActivationVerificationResponse:
        return self._request("POST", VERIFY_ACTIVATION, ActivationVerificationResponse, request.model_dump(), idempotent=False, access_token=access_token)

    def deactivate(self, request: DeactivationRequest, access_token: str) -> DeactivationResponse:
        return self._request("POST", DEACTIVATE, DeactivationResponse, request.model_dump(), idempotent=False, access_token=access_token)

    def _request(self, method: str, path: str, model: type[T], payload: dict[str, Any] | None = None,
                 *, idempotent: bool = True, access_token: str | None = None) -> T:
        request_id = str(uuid.uuid4())
        headers = {"Accept": "application/json", "User-Agent": self.config.user_agent,
                   "X-Request-ID": request_id}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        url = f"{self.config.base_url}{path}"
        attempts = self.config.retry_count if idempotent else 0
        for attempt in range(attempts + 1):
            started = time.monotonic()
            try:
                response = self.session.request(
                    method, url, json=payload, headers=headers,
                    timeout=(self.config.connect_timeout, self.config.read_timeout), verify=True,
                )
                duration_ms = round((time.monotonic() - started) * 1000, 2)
                logger.info("api_request", extra={"method": method, "endpoint": path,
                    "duration_ms": duration_ms, "result": response.status_code,
                    "request_id": request_id})
                if response.status_code in {408, 425, 429, 500, 502, 503, 504} and attempt < attempts:
                    self.sleep(min(self.config.retry_backoff * (2 ** attempt), 30))
                    continue
                return self._parse_response(response, model)
            except requests.exceptions.ConnectTimeout as exc:
                if attempt < attempts and idempotent:
                    self.sleep(min(self.config.retry_backoff * (2 ** attempt), 30)); continue
                raise ConnectionTimeoutError("Unable to connect to the licensing platform") from exc
            except requests.exceptions.ReadTimeout as exc:
                if attempt < attempts and idempotent:
                    self.sleep(min(self.config.retry_backoff * (2 ** attempt), 30)); continue
                raise RequestTimeoutError("The licensing platform response timed out") from exc
            except requests.exceptions.SSLError as exc:
                raise TlsFailureError("TLS verification failed for the licensing platform") from exc
            except requests.exceptions.ConnectionError as exc:
                if attempt < attempts and idempotent:
                    self.sleep(min(self.config.retry_backoff * (2 ** attempt), 30)); continue
                raise NetworkUnavailableError("The licensing platform is unavailable") from exc

    def _parse_response(self, response: requests.Response, model: type[T]) -> T:
        status_map = {401: AuthenticationRequiredError, 403: AuthorizationDeniedError,
                      404: ResourceNotFoundError, 409: ConflictError,
                      429: RateLimitExceededError, 426: UnsupportedClientVersionError}
        if response.status_code in status_map:
            error_type = status_map[response.status_code]
            if response.status_code == 401:
                error_type = AuthenticationExpiredError
            raise error_type("The licensing platform rejected the request")
        if response.status_code >= 500:
            raise ServerUnavailableError("The licensing platform reported a server error")
        if not 200 <= response.status_code < 300:
            raise UnknownApiError("The licensing platform returned an unexpected status")
        try:
            data = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise InvalidServerResponseError("The licensing platform returned invalid JSON") from exc
        try:
            return model.model_validate(data)
        except ValidationError as exc:
            raise InvalidServerResponseError("The licensing platform returned an invalid response") from exc
