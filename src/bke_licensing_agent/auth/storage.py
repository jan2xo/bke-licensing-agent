import json
from typing import Protocol

import keyring
from keyring.errors import KeyringError

from .errors import CorruptedSecureStorageError, SecureStorageUnavailableError


class SecureCredentialStore(Protocol):
    def save(self, account: str, value: dict) -> None: ...
    def load(self, account: str) -> dict | None: ...
    def delete(self, account: str) -> None: ...


class KeyringCredentialStore:
    service = "bke-licensing-agent"

    def save(self, account: str, value: dict) -> None:
        try:
            keyring.set_password(self.service, account, json.dumps(value))
        except (KeyringError, RuntimeError) as exc:
            raise SecureStorageUnavailableError("Secure credential storage is unavailable") from exc

    def load(self, account: str) -> dict | None:
        try:
            raw = keyring.get_password(self.service, account)
        except (KeyringError, RuntimeError) as exc:
            raise SecureStorageUnavailableError("Secure credential storage is unavailable") from exc
        if raw is None:
            return None
        try:
            value = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise CorruptedSecureStorageError("Stored session data is corrupted") from exc
        if not isinstance(value, dict):
            raise CorruptedSecureStorageError("Stored session data is invalid")
        return value

    def delete(self, account: str) -> None:
        try:
            keyring.delete_password(self.service, account)
        except keyring.errors.PasswordDeleteError:
            return
        except (KeyringError, RuntimeError) as exc:
            raise SecureStorageUnavailableError("Secure credential storage is unavailable") from exc


def get_secure_store(provider: str) -> SecureCredentialStore:
    if provider != "keyring":
        raise SecureStorageUnavailableError("The configured secure storage provider is unavailable")
    backend = keyring.get_keyring()
    backend_name = f"{backend.__class__.__module__}.{backend.__class__.__name__}".lower()
    if any(marker in backend_name for marker in ("null", "fail", "plaintext", "plain")):
        raise SecureStorageUnavailableError("The configured keyring backend is not secure")
    if getattr(backend, "priority", 1) <= 0:
        raise SecureStorageUnavailableError("The configured keyring backend is unavailable")
    return KeyringCredentialStore()
