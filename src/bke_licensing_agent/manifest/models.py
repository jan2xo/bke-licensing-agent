from pathlib import Path
from typing import Any, Literal

from packaging.version import Version, InvalidVersion
from pydantic import BaseModel, ValidationError, field_validator


class Manifest(BaseModel):
    schemaVersion: Literal[1]
    productId: str
    displayName: str
    publisher: str | None = None
    version: str
    entryPoint: str
    icon: str | None = None
    updateChannel: str
    minimumAgentVersion: str
    platform: str
    architecture: str

    model_config = {
        "extra": "forbid",
    }

    @field_validator("version", "minimumAgentVersion")
    @classmethod
    def validate_semver(cls, value: str) -> str:
        try:
            Version(value)
        except InvalidVersion as exc:
            raise ValueError(f"Invalid semantic version: {value}") from exc
        return value

    @field_validator("entryPoint")
    @classmethod
    def validate_entry_point(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("entryPoint must not be empty")
        # Treat Windows separators as separators even when validating on Unix.
        portable_parts = value.replace("\\", "/").split("/")
        if value.startswith(("/", "\\")) or (len(value) >= 2 and value[1] == ":"):
            raise ValueError("entryPoint must be a relative path")
        if ".." in portable_parts:
            raise ValueError("entryPoint must not escape the product directory")
        return value

    @field_validator("icon")
    @classmethod
    def validate_icon(cls, value: str | None) -> str | None:
        if value is None:
            return value
        portable_parts = value.replace("\\", "/").split("/")
        if value.startswith(("/", "\\")) or (len(value) >= 2 and value[1] == ":"):
            raise ValueError("icon must be a relative path")
        if ".." in portable_parts:
            raise ValueError("icon must not escape the product directory")
        return value

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()
