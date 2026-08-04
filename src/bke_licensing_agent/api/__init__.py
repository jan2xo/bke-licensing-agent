"""Typed client for the BKE Licensing Platform."""

from .client import LicensingPlatformClient
from .config import ApiConfig
from .errors import ApiError

__all__ = ["ApiConfig", "ApiError", "LicensingPlatformClient"]
