"""Safe activation diagnostics; never carries secret or lease material."""

from dataclasses import dataclass
from typing import Any

from ..api.errors import (
    AuthorizationDeniedError, ConflictError, ConnectionTimeoutError,
    InvalidServerResponseError, NetworkUnavailableError, RateLimitExceededError,
    RequestTimeoutError, ResourceNotFoundError, ServerUnavailableError,
    TlsFailureError, UnknownApiError,
)
from .errors import ActivationDeniedError, ActivationVerificationError
from .lease import (
    LeaseInvalidSignatureError, LeaseMalformedError, LeaseUnknownKeyError,
)
from .license_repository import LicenseRecordPersistenceError


@dataclass(frozen=True)
class ActivationDiagnostic:
    category: str
    stage: str

    def as_dict(self) -> dict[str, str]:
        return {"category": self.category, "stage": self.stage}


def classify_activation_failure(exc: Exception) -> ActivationDiagnostic:
    if isinstance(exc, (ConnectionTimeoutError, RequestTimeoutError,
                        NetworkUnavailableError, TlsFailureError)):
        return ActivationDiagnostic("platform_unreachable", "platform_request")
    if isinstance(exc, (AuthorizationDeniedError, ConflictError,
                        ResourceNotFoundError, RateLimitExceededError,
                        ServerUnavailableError)):
        return ActivationDiagnostic("platform_http_error", "platform_request")
    if isinstance(exc, (InvalidServerResponseError, UnknownApiError)):
        return ActivationDiagnostic("malformed_platform_response", "platform_response")
    if isinstance(exc, LeaseUnknownKeyError):
        return ActivationDiagnostic("trusted_key_unavailable", "lease_verification")
    if isinstance(exc, LeaseInvalidSignatureError):
        return ActivationDiagnostic("signature_verification_failed", "lease_verification")
    if isinstance(exc, LeaseMalformedError):
        return ActivationDiagnostic("malformed_platform_response", "lease_verification")
    if isinstance(exc, ActivationVerificationError):
        return ActivationDiagnostic("lease_binding_mismatch", "lease_verification")
    if isinstance(exc, ActivationDeniedError):
        return ActivationDiagnostic("activation_rejected", "authorization")
    if isinstance(exc, LicenseRecordPersistenceError):
        return ActivationDiagnostic("persistence_failed", "binding_persistence")
    return ActivationDiagnostic("unsupported_response", "activation")


def emit_activation_diagnostic(sink: Any, diagnostic: ActivationDiagnostic) -> None:
    if sink is not None:
        sink(diagnostic.as_dict())
