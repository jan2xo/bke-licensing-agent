from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AuthModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(AuthModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class TokenPair(AuthModel):
    access_token: str = Field(min_length=1)
    refresh_token: str = Field(min_length=1)
    access_expires_at: datetime
    refresh_expires_at: datetime


class LoginResponse(AuthModel):
    tokens: TokenPair
    session: "SessionInfo"


class RefreshRequest(AuthModel):
    refresh_token: str = Field(min_length=1)


class RefreshResponse(AuthModel):
    tokens: TokenPair


class LogoutRequest(AuthModel):
    refresh_token: str = Field(min_length=1)


class LogoutResponse(AuthModel):
    success: bool


class SessionInfo(AuthModel):
    session_id: str
    account_id: str
    expires_at: datetime


class AuthenticationState(AuthModel):
    state: Literal["authenticated", "expired", "revoked", "missing"]
    session: SessionInfo | None = None


class ValidationResponse(AuthModel):
    valid: bool
    session: SessionInfo | None = None
