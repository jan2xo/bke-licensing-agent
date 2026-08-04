import logging
import time

from ..api.client import LicensingPlatformClient
from ..api.errors import AuthenticationExpiredError, AuthorizationDeniedError
from .errors import ExpiredSessionError, InvalidCredentialsError, RefreshFailedError, RevokedSessionError
from .models import AuthenticationState, LoginRequest, SessionInfo, TokenPair
from .session import SessionManager

logger = logging.getLogger(__name__)


class AuthenticationService:
    def __init__(self, client: LicensingPlatformClient, sessions: SessionManager):
        self.client = client
        self.sessions = sessions

    def login(self, request: LoginRequest) -> SessionInfo:
        started = time.monotonic()
        try:
            response = self.client.login(request)
        except AuthenticationExpiredError as exc:
            self._log("login", started, False)
            raise InvalidCredentialsError("The supplied credentials were not accepted") from exc
        self.sessions.establish(response.tokens, response.session)
        self._log("login", started, True)
        return response.session

    def refresh_session(self) -> SessionInfo:
        started = time.monotonic()
        try:
            session = self.sessions.refresh(self.client)
        except (AuthenticationExpiredError, AuthorizationDeniedError) as exc:
            self._log("refresh", started, False)
            raise RefreshFailedError("The session could not be refreshed") from exc
        self._log("refresh", started, True)
        return session

    def ensure_fresh_session(self) -> SessionInfo:
        started = time.monotonic()
        session = self.sessions.refresh_if_needed(self.client)
        self._log("refresh_if_needed", started, True)
        return session

    def logout(self) -> None:
        started = time.monotonic()
        self.sessions.logout(self.client)
        self._log("logout", started, True)

    def validate_session(self) -> AuthenticationState:
        started = time.monotonic()
        state = self.sessions.validate(self.client)
        self._log("validate", started, state.state == "authenticated")
        return state

    def current_session(self) -> SessionInfo:
        return self.sessions.current_session()

    def _log(self, event: str, started: float, success: bool) -> None:
        logger.info("authentication_event", extra={"event": event,
            "duration_ms": round((time.monotonic() - started) * 1000, 2), "success": success,
            "provider": self.sessions.provider_name})
