from pydantic import BaseModel, ConfigDict, Field, model_validator
from urllib.parse import urlparse


class ApiConfig(BaseModel):
    """Validated runtime settings for the licensing API client."""

    model_config = ConfigDict(extra="forbid")

    base_url: str
    connect_timeout: float = Field(default=5.0, gt=0)
    read_timeout: float = Field(default=15.0, gt=0)
    retry_count: int = Field(default=2, ge=0, le=5)
    retry_backoff: float = Field(default=0.25, ge=0, le=30)
    user_agent: str = "bke-licensing-agent"
    client_version: str = "0.1.0"
    environment: str = "production"
    allow_insecure_local: bool = False

    @model_validator(mode="after")
    def validate_base_url(self):
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain a query or fragment")
        if parsed.scheme != "https" and not (self.allow_insecure_local and self.environment in {"local", "test"}):
            raise ValueError("HTTPS is required outside explicitly allowed local/test environments")
        self.base_url = self.base_url.rstrip("/")
        return self
