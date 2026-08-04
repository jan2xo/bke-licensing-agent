import secrets
import threading

from ..auth.errors import CorruptedSecureStorageError
from ..auth.storage import SecureCredentialStore


class InstallationIdentity:
    """Stable agent installation identity, distinct from a server device ID."""

    account = "installation-identity"

    def __init__(self, store: SecureCredentialStore):
        self.store = store
        self._generation = 0
        self._lock = threading.Lock()

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def load_or_create(self) -> str:
        value = self.store.load(self.account)
        if value is None:
            installation_id = secrets.token_urlsafe(32)
            self.store.save(self.account, {"installation_id": installation_id})
            return installation_id
        installation_id = value.get("installation_id")
        if not isinstance(installation_id, str) or len(installation_id) < 32:
            raise CorruptedSecureStorageError("Installation identity is corrupted")
        return installation_id

    def reset(self) -> str:
        with self._lock:
            self.store.delete(self.account)
            self._generation += 1
            value = secrets.token_urlsafe(32)
            self.store.save(self.account, {"installation_id": value})
            return value
