"""Signed offline lease parsing and verification."""

import base64
import binascii
import json
from datetime import datetime, timezone
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class LeaseVerificationError(Exception):
    """Base class for fail-closed lease verification failures."""


class LeaseMalformedError(LeaseVerificationError): pass
class LeaseUnknownKeyError(LeaseVerificationError): pass
class LeaseInvalidSignatureError(LeaseVerificationError): pass
class LeaseUnsupportedAlgorithmError(LeaseVerificationError): pass
class LeaseRevokedError(LeaseVerificationError): pass
class LeaseSupersededError(LeaseVerificationError): pass


class LeaseMetadataError(Exception):
    """Base class for fail-closed local metadata errors."""


class LeaseMetadataCorruptError(LeaseMetadataError): pass
class LeaseMetadataPersistenceError(LeaseMetadataError): pass
class LeaseMetadataSchemaError(LeaseMetadataError): pass


class LicenseLease(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lease_id: str
    generation: int = Field(ge=0)
    product_id: str
    installation_id: str
    device_id: str
    version: str
    issuer: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    key_id: str
    algorithm: str
    revoked: bool = False
    superseded_by: str | None = None


class LeaseEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload: str
    signature: str
    key_id: str
    algorithm: str


class LeaseMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lease_id: str
    product_id: str
    installation_id: str
    device_id: str
    generation: int
    status: str
    issued_at: datetime
    expires_at: datetime
    issuer: str
    key_id: str
    verified_at: datetime


class TrustedKeyMetadata(BaseModel):
    key_id: str
    public_key: str
    algorithm: str


class TrustedKeyMetadataResponse(BaseModel):
    keys: list[TrustedKeyMetadata]


class LeaseMetadataStore(Protocol):
    def save(self, metadata: LeaseMetadata) -> None: ...
    def load(self, lease_id: str) -> LeaseMetadata | None: ...


def _decode(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LeaseMalformedError(f"Invalid lease {label}") from exc


class LeaseVerifier:
    def __init__(self, trusted_keys: dict[str, str], *, algorithm: str = "Ed25519"):
        self.trusted_keys = dict(trusted_keys)
        self.algorithm = algorithm

    def verify(self, raw: dict[str, Any] | str) -> LicenseLease:
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
            envelope = LeaseEnvelope.model_validate(data)
        except (json.JSONDecodeError, TypeError, ValidationError) as exc:
            raise LeaseMalformedError("Malformed lease envelope") from exc
        if envelope.algorithm != self.algorithm:
            raise LeaseUnsupportedAlgorithmError("Unsupported lease signature algorithm")
        if envelope.key_id not in self.trusted_keys:
            raise LeaseUnknownKeyError("Lease signing key is not trusted")
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            key = serialization.load_pem_public_key(self.trusted_keys[envelope.key_id].encode())
            if not isinstance(key, Ed25519PublicKey):
                raise LeaseInvalidSignatureError("Trusted key is not Ed25519")
            key.verify(_decode(envelope.signature, "signature"), envelope.payload.encode())
        except LeaseVerificationError:
            raise
        except InvalidSignature as exc:
            raise LeaseInvalidSignatureError("Lease signature is invalid") from exc
        except Exception as exc:
            raise LeaseMalformedError("Lease signature could not be verified") from exc
        try:
            lease = LicenseLease.model_validate(json.loads(envelope.payload))
        except (json.JSONDecodeError, TypeError, ValidationError) as exc:
            raise LeaseMalformedError("Malformed lease payload") from exc
        if lease.key_id != envelope.key_id or lease.algorithm != envelope.algorithm:
            raise LeaseMalformedError("Lease key metadata does not match envelope")
        if lease.revoked:
            raise LeaseRevokedError("Lease is revoked")
        if lease.superseded_by is not None:
            raise LeaseSupersededError("Lease has been superseded")
        return lease


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
