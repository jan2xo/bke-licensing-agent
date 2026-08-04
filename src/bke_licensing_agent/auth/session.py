import threading
from datetime import datetime, timezone

from ..api.client import LicensingPlatformClient
from .errors import ExpiredSessionError, MissingSessionError
from .models import AuthenticationState, LogoutRequest, RefreshRequest, SessionInfo, TokenPair
from .storage import SecureCredentialStore, get_secure_store


class SessionManager:
    """Owns session state and generation-safe, deduplicated refreshes."""

    def __init__(self, config, store: SecureCredentialStore | None = None, account: str = "current"):
        self.config = config
        self.store = store or get_secure_store(config.secure_storage_provider)
        self.account = account
        self.provider_name = config.secure_storage_provider
        self._session: SessionInfo | None = None
        self._generation = 0
        self._condition = threading.Condition()
        self._refresh_inflight = False
        self._refresh_generation: int | None = None
        self._last_refresh_generation: int | None = None
        self._last_refresh_session: SessionInfo | None = None
        self._refresh_error: Exception | None = None

    def establish(self, tokens: TokenPair, session: SessionInfo) -> None:
        with self._condition:
            self._generation += 1
            self.store.save(self.account, tokens.model_dump(mode="json"))
            self._session = session
            self._last_refresh_generation = None
            self._last_refresh_session = None
            self._refresh_error = None
            self._condition.notify_all()

    def current_session(self) -> SessionInfo:
        with self._condition:
            if self._session is None:
                raise MissingSessionError("No authenticated session is available")
            if self._session.expires_at <= datetime.now(timezone.utc):
                raise ExpiredSessionError("The authenticated session has expired")
            return self._session

    def access_token(self) -> str:
        stored = self.store.load(self.account)
        if not stored or not stored.get("access_token"):
            raise MissingSessionError("No authenticated session is available")
        return str(stored["access_token"])

    @property
    def generation(self) -> int:
        with self._condition:
            return self._generation

    def is_generation_current(self, generation: int) -> bool:
        with self._condition:
            return self._generation == generation and self._session is not None

    def needs_refresh(self) -> bool:
        stored = self.store.load(self.account)
        if not stored or not stored.get("access_expires_at"):
            raise MissingSessionError("No authenticated session is available")
        expires = datetime.fromisoformat(str(stored["access_expires_at"]).replace("Z", "+00:00"))
        return (expires - datetime.now(timezone.utc)).total_seconds() <= self.config.refresh_threshold

    def refresh_if_needed(self, client: LicensingPlatformClient) -> SessionInfo:
        if not self.needs_refresh():
            return self.current_session()
        return self.refresh(client)

    def refresh(self, client: LicensingPlatformClient) -> SessionInfo:
        with self._condition:
            if self._last_refresh_generation == self._generation and self._last_refresh_session is not None:
                return self._last_refresh_session
            if self._refresh_inflight:
                generation = self._refresh_generation
                while self._refresh_inflight:
                    self._condition.wait()
                if generation != self._generation:
                    raise MissingSessionError("The session changed while refresh was in progress")
                if self._refresh_error is not None:
                    raise self._refresh_error
                if self._last_refresh_generation == self._generation and self._last_refresh_session is not None:
                    return self._last_refresh_session
                raise MissingSessionError("Refresh did not produce an authenticated session")
            stored = self.store.load(self.account)
            if not stored or not stored.get("refresh_token") or self._session is None:
                raise MissingSessionError("No refresh session is available")
            generation = self._generation
            refresh_token = str(stored["refresh_token"])
            self._refresh_inflight = True
            self._refresh_generation = generation
            self._refresh_error = None

        try:
            response = client.refresh_session(RefreshRequest(refresh_token=refresh_token))
        except Exception as exc:
            with self._condition:
                self._refresh_error = exc
                self._refresh_inflight = False
                self._refresh_generation = None
                self._condition.notify_all()
            raise

        with self._condition:
            if generation != self._generation or self._session is None:
                error = MissingSessionError("The session changed while refresh was in progress")
                self._refresh_error = error
                self._refresh_inflight = False
                self._refresh_generation = None
                self._condition.notify_all()
                raise error
            self.store.save(self.account, response.tokens.model_dump(mode="json"))
            self._last_refresh_generation = generation
            self._last_refresh_session = self._session
            self._refresh_inflight = False
            self._refresh_generation = None
            self._condition.notify_all()
            return self._session

    def logout(self, client: LicensingPlatformClient) -> None:
        with self._condition:
            self._generation += 1
            stored = self.store.load(self.account)
            self._session = None
            self._last_refresh_generation = None
            self._last_refresh_session = None
            self._refresh_error = MissingSessionError("The session was invalidated")
            self.store.delete(self.account)
            self._condition.notify_all()
        if stored and stored.get("refresh_token"):
            client.logout(LogoutRequest(refresh_token=stored["refresh_token"]), access_token=stored.get("access_token"))

    def validate(self, client: LicensingPlatformClient) -> AuthenticationState:
        try:
            session = self.current_session()
            response = client.validate_session(self.access_token())
        except ExpiredSessionError:
            return AuthenticationState(state="expired")
        except MissingSessionError:
            return AuthenticationState(state="missing")
        if not response.valid:
            with self._condition:
                self._generation += 1
                self._session = None
                self._last_refresh_generation = None
                self._last_refresh_session = None
                self._refresh_error = MissingSessionError("The session was revoked")
                self.store.delete(self.account)
                self._condition.notify_all()
            return AuthenticationState(state="revoked")
        return AuthenticationState(state="authenticated", session=session)
