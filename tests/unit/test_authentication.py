from datetime import datetime, timedelta, timezone
import logging
import threading

import pytest

from bke_licensing_agent.api.config import ApiConfig
from bke_licensing_agent.auth.errors import (
    ExpiredSessionError, MissingSessionError, SecureStorageUnavailableError,
)
from bke_licensing_agent.auth.models import (
    LoginRequest, LoginResponse, SessionInfo, TokenPair, ValidationResponse,
)
from bke_licensing_agent.auth.service import AuthenticationService
from bke_licensing_agent.auth.session import SessionManager
from bke_licensing_agent.auth.storage import KeyringCredentialStore, get_secure_store


def future(minutes=60):
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


def tokens():
    return TokenPair(access_token="access-secret", refresh_token="refresh-secret",
        access_expires_at=future(), refresh_expires_at=future(120))


def session():
    return SessionInfo(session_id="session-1", account_id="account-1", expires_at=future())


class MemoryStore:
    def __init__(self, value=None): self.value = value
    def save(self, account, value): self.value = value
    def load(self, account): return self.value
    def delete(self, account): self.value = None


class FakeClient:
    def __init__(self):
        self.response = LoginResponse(tokens=tokens(), session=session())
        self.valid = True
        self.calls = []

    def login(self, request): self.calls.append(("login", request)); return self.response
    def refresh_session(self, request): self.calls.append(("refresh", request)); return type("R", (), {"tokens": tokens()})()
    def logout(self, request, access_token=None): self.calls.append(("logout", request, access_token)); return type("R", (), {"success": True})()
    def validate_session(self, access_token): self.calls.append(("validate", access_token)); return ValidationResponse(valid=self.valid, session=session())


def manager(store=None):
    return SessionManager(ApiConfig(base_url="https://api.example.test"), store or MemoryStore())


def test_login_refresh_validate_and_logout_keep_tokens_out_of_logs(caplog):
    fake = FakeClient()
    service = AuthenticationService(fake, manager())
    with caplog.at_level(logging.INFO):
        assert service.login(LoginRequest(username="user", password="password")).session_id == "session-1"
        service.refresh_session()
        assert service.validate_session().state == "authenticated"
        service.logout()
    output = caplog.text
    assert "access-secret" not in output
    assert "refresh-secret" not in output
    assert "password" not in output
    assert service.sessions._session is None


def test_missing_and_expired_sessions_are_rejected():
    current = manager()
    with pytest.raises(MissingSessionError): current.current_session()
    current.establish(tokens(), SessionInfo(session_id="s", account_id="a", expires_at=future(-1)))
    with pytest.raises(ExpiredSessionError): current.current_session()


def test_revoked_session_is_reported_and_cleared():
    fake = FakeClient(); fake.valid = False
    sessions = manager(); sessions.establish(tokens(), session())
    assert sessions.validate(fake).state == "revoked"
    with pytest.raises(MissingSessionError): sessions.current_session()


def test_secure_store_failure_is_not_silenced():
    class BrokenStore(MemoryStore):
        def save(self, account, value): raise SecureStorageUnavailableError("unavailable")
    with pytest.raises(SecureStorageUnavailableError): manager(BrokenStore()).establish(tokens(), session())


def test_refresh_is_serialized_by_session_manager():
    fake = FakeClient(); sessions = manager(); sessions.establish(tokens(), session())
    assert sessions.refresh(fake).session_id == "session-1"
    assert [call[0] for call in fake.calls] == ["refresh"]


class BlockingClient(FakeClient):
    def __init__(self, failure=None):
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()
        self.failure = failure
        self.response = type("R", (), {"tokens": TokenPair(
            access_token="new-access", refresh_token="new-refresh",
            access_expires_at=future(), refresh_expires_at=future(120))})()

    def refresh_session(self, request):
        self.calls.append(("refresh", request))
        self.started.set()
        self.release.wait(timeout=2)
        if self.failure:
            raise self.failure
        return self.response


def test_concurrent_refresh_callers_share_one_result():
    fake = BlockingClient(); sessions = manager(); sessions.establish(tokens(), session())
    results = []
    threads = [threading.Thread(target=lambda: results.append(sessions.refresh(fake))) for _ in range(2)]
    for thread in threads: thread.start()
    assert fake.started.wait(timeout=2)
    fake.release.set()
    for thread in threads: thread.join(timeout=2)
    assert len(fake.calls) == 1
    assert results[0] is results[1]


def test_logout_during_refresh_cannot_restore_credentials():
    fake = BlockingClient(); store = MemoryStore(); sessions = manager(store); sessions.establish(tokens(), session())
    error = []
    worker = threading.Thread(target=lambda: _capture(error, sessions.refresh, fake))
    worker.start(); assert fake.started.wait(timeout=2)
    sessions.logout(fake)
    fake.release.set(); worker.join(timeout=2)
    assert isinstance(error[0], MissingSessionError)
    assert store.value is None
    assert len([call for call in fake.calls if call[0] == "refresh"]) == 1


def test_stale_refresh_cannot_overwrite_newer_login():
    fake = BlockingClient(); store = MemoryStore(); sessions = manager(store); sessions.establish(tokens(), session())
    error = []
    worker = threading.Thread(target=lambda: _capture(error, sessions.refresh, fake))
    worker.start(); assert fake.started.wait(timeout=2)
    newer = TokenPair(access_token="latest-access", refresh_token="latest-refresh", access_expires_at=future(), refresh_expires_at=future(120))
    sessions.establish(newer, SessionInfo(session_id="latest", account_id="a", expires_at=future()))
    fake.release.set(); worker.join(timeout=2)
    assert isinstance(error[0], MissingSessionError)
    assert store.value["access_token"] == "latest-access"


def test_refresh_failure_does_not_partially_update_state():
    fake = BlockingClient(failure=RuntimeError("refresh failed")); store = MemoryStore(); sessions = manager(store); sessions.establish(tokens(), session())
    error = []
    worker = threading.Thread(target=lambda: _capture(error, sessions.refresh, fake))
    worker.start(); assert fake.started.wait(timeout=2); fake.release.set(); worker.join(timeout=2)
    assert isinstance(error[0], RuntimeError)
    assert store.value["access_token"] == "access-secret"


def _capture(target, function, *args):
    try:
        function(*args)
    except Exception as exc:  # test helper captures propagation
        target.append(exc)


def test_keyring_save_load_delete_and_missing(monkeypatch):
    values = {}
    monkeypatch.setattr("keyring.set_password", lambda service, account, value: values.update({(service, account): value}))
    monkeypatch.setattr("keyring.get_password", lambda service, account: values.get((service, account)))
    monkeypatch.setattr("keyring.delete_password", lambda service, account: values.pop((service, account)))
    store = KeyringCredentialStore(); store.save("current", {"access_token": "secret"})
    assert store.load("current") == {"access_token": "secret"}
    store.delete("current"); assert store.load("current") is None


@pytest.mark.parametrize("raw", ["not-json", "[]"])
def test_keyring_corruption_is_rejected(monkeypatch, raw):
    monkeypatch.setattr("keyring.get_password", lambda *_: raw)
    with pytest.raises(Exception): KeyringCredentialStore().load("current")


def test_keyring_backend_is_validated(monkeypatch):
    class NullKeyring: priority = 0
    monkeypatch.setattr("keyring.get_keyring", lambda: NullKeyring())
    with pytest.raises(SecureStorageUnavailableError): get_secure_store("keyring")


def test_revoked_validation_deletes_credentials():
    fake = FakeClient(); fake.valid = False; store = MemoryStore(); sessions = manager(store); sessions.establish(tokens(), session())
    assert sessions.validate(fake).state == "revoked"
    assert store.value is None
