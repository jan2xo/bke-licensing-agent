import hashlib
import platform

FINGERPRINT_SCHEMA_VERSION = "bke-device-v1"


class DeviceFingerprint:
    def __init__(self, signals: dict[str, str] | None = None):
        self.signals = signals or {
            "platform": platform.system().lower(),
            "os_version": platform.release().lower(),
            "architecture": platform.machine().lower(),
        }

    def calculate(self) -> str:
        normalized = "|".join(f"{key}={str(self.signals[key]).strip().lower()}" for key in sorted(self.signals))
        return hashlib.sha256(f"{FINGERPRINT_SCHEMA_VERSION}|{normalized}".encode()).hexdigest()
