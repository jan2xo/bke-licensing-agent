"""Free Licensing Agent self-update discovery and GitHub catalog handoff."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from packaging.version import InvalidVersion, Version

from .license_center.native_launcher import _run_windows_interactive
from .version import __version__

AGENT_PRODUCT_ID = "bke-licensing-agent"
CATALOG_REPOSITORY = "jan2xo/bke-software-catalog"
CHECK_INTERVAL = timedelta(hours=6)
REMIND_AFTER = timedelta(hours=24)
MAX_INSTALLER_BYTES = 512 * 1024 * 1024


class AgentSelfUpdateError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentUpdateOffer:
    current_version: str
    latest_version: str
    download_url: str
    release_notes: str | None
    required: bool


class AgentSelfUpdateCoordinator:
    """Ask Digital Solutions for Agent releases and install approved catalog assets."""

    def __init__(
        self,
        *,
        state_root: Path,
        platform_base_url: str,
        current_version: str | None = None,
        clock=lambda: datetime.now(timezone.utc),
    ) -> None:
        self.state_root = state_root / "self-update"
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.platform_base_url = platform_base_url.rstrip("/")
        self.current_version = (
            current_version
            or os.getenv("BKE_AGENT_SELF_UPDATE_VERSION")
            or __version__
        ).strip()
        self.clock = clock

    @staticmethod
    def _target() -> tuple[str, str]:
        if os.name != "nt":
            raise AgentSelfUpdateError("Agent self-update is currently supported only on Windows")
        machine = platform.machine().lower()
        if machine in {"amd64", "x86_64", "x64", "arm64", "aarch64"}:
            # Until a native ARM64 Agent package is published, Windows on ARM64
            # intentionally consumes the existing x86_64 installer via Windows'
            # x64 application emulation layer.
            return "windows", "x86_64"
        raise AgentSelfUpdateError("unsupported Agent architecture")

    @staticmethod
    def _validate_catalog_url(value: str) -> str:
        try:
            parsed = urlparse(value)
        except ValueError as exc:
            raise AgentSelfUpdateError("invalid software catalog URL") from exc
        expected = f"/{CATALOG_REPOSITORY}/releases/download/"
        if parsed.scheme != "https" or parsed.hostname != "github.com" or not parsed.path.startswith(expected):
            raise AgentSelfUpdateError("Agent update URL is outside the BKE software catalog")
        if not parsed.path.lower().endswith(".exe"):
            raise AgentSelfUpdateError("Windows Agent update must be an executable installer")
        return value

    def check(self) -> AgentUpdateOffer | None:
        platform_name, architecture = self._target()
        try:
            Version(self.current_version)
        except InvalidVersion as exc:
            raise AgentSelfUpdateError("installed Agent version is invalid") from exc

        try:
            response = requests.get(
                f"{self.platform_base_url}/api/licensing-agent/update",
                params={
                    "version": self.current_version,
                    "platform": platform_name,
                    "architecture": architecture,
                },
                headers={"accept": "application/json", "user-agent": f"BKE-Licensing-Agent/{self.current_version}"},
                timeout=10,
            )
            response.raise_for_status()
            document = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise AgentSelfUpdateError("Agent update authority is unavailable") from exc

        if not isinstance(document, dict):
            raise AgentSelfUpdateError("Agent update response is malformed")
        if document.get("productId") != AGENT_PRODUCT_ID:
            raise AgentSelfUpdateError("Agent update response product mismatch")
        if document.get("source") != "bke-software-catalog":
            raise AgentSelfUpdateError("Agent update response source mismatch")
        if document.get("currentVersion") != self.current_version:
            raise AgentSelfUpdateError("Agent update response version mismatch")

        latest = document.get("latestVersion")
        available = document.get("updateAvailable")
        if not isinstance(latest, str) or not isinstance(available, bool):
            raise AgentSelfUpdateError("Agent update response is malformed")
        try:
            current_version = Version(self.current_version)
            latest_version = Version(latest)
        except InvalidVersion as exc:
            raise AgentSelfUpdateError("Agent update response contains an invalid version") from exc

        if not available:
            if latest_version > current_version:
                raise AgentSelfUpdateError("Agent update authority returned an inconsistent decision")
            return None
        if latest_version <= current_version:
            raise AgentSelfUpdateError("Agent update authority returned an invalid newer-version decision")

        download_url = document.get("downloadUrl")
        if not isinstance(download_url, str) or not download_url:
            raise AgentSelfUpdateError("Agent update response omitted the download URL")
        release_notes = document.get("releaseNotes")
        if release_notes is not None and not isinstance(release_notes, str):
            raise AgentSelfUpdateError("Agent update release notes are malformed")

        return AgentUpdateOffer(
            current_version=self.current_version,
            latest_version=latest,
            download_url=self._validate_catalog_url(download_url),
            release_notes=release_notes,
            required=bool(document.get("required", False)),
        )

    def _state_path(self) -> Path:
        return self.state_root / "state.json"

    def _read_state(self) -> dict[str, object]:
        try:
            value = json.loads(self._state_path().read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_state(self, value: dict[str, object]) -> None:
        path = self._state_path()
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        temporary.replace(path)

    def _suppressed(self, offer: AgentUpdateOffer) -> bool:
        state = self._read_state()
        if state.get("latest_version") != offer.latest_version:
            return False
        remind_after = state.get("remind_after")
        if not isinstance(remind_after, str):
            return False
        try:
            return self.clock() < datetime.fromisoformat(remind_after.replace("Z", "+00:00"))
        except ValueError:
            return False

    def _suppress(self, offer: AgentUpdateOffer) -> None:
        until = self.clock() + REMIND_AFTER
        self._write_state({
            "latest_version": offer.latest_version,
            "remind_after": until.isoformat().replace("+00:00", "Z"),
        })

    @staticmethod
    def _license_center_executable() -> Path:
        name = "bke-license-center.exe" if sys.platform == "win32" else "bke-license-center"
        agent_dir = Path(sys.executable).resolve().parent
        candidates = (
            agent_dir / name,
            agent_dir.parent / "license-center" / name,
            agent_dir.parent / "bke-license-center" / name,
        )
        return next((candidate for candidate in candidates if candidate.is_file()), candidates[0])

    def prompt(self, offer: AgentUpdateOffer) -> str:
        executable = self._license_center_executable()
        if not executable.is_file():
            raise AgentSelfUpdateError("native License Center is not installed")
        arguments = [
            str(executable),
            "--agent-update-prompt",
            "--current-version", offer.current_version,
            "--latest-version", offer.latest_version,
        ]
        if offer.release_notes:
            arguments.extend(("--release-notes", offer.release_notes[:2000]))
        completed = _run_windows_interactive(arguments, shell=False, check=False)
        if completed.returncode == 0:
            return "update"
        if completed.returncode == 2:
            return "later"
        raise AgentSelfUpdateError("Agent update prompt failed")

    @staticmethod
    def _approved_redirect(url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return False
        host = parsed.hostname.lower()
        return host == "github.com" or host.endswith(".githubusercontent.com")

    def download(self, offer: AgentUpdateOffer) -> Path:
        self._validate_catalog_url(offer.download_url)
        destination = self.state_root / "downloads" / f"BKE-Licensing-Agent-{offer.latest_version}-Windows-x64.exe"
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(".download")
        temporary.unlink(missing_ok=True)

        try:
            with requests.get(
                offer.download_url,
                stream=True,
                allow_redirects=True,
                headers={"user-agent": f"BKE-Licensing-Agent/{self.current_version}"},
                timeout=(10, 60),
            ) as response:
                response.raise_for_status()
                if not self._approved_redirect(response.url):
                    raise AgentSelfUpdateError("GitHub release redirected outside approved asset hosts")
                announced = response.headers.get("content-length")
                if announced is not None and int(announced) > MAX_INSTALLER_BYTES:
                    raise AgentSelfUpdateError("Agent installer exceeds the download limit")
                count = 0
                with temporary.open("wb") as output:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if not chunk:
                            continue
                        count += len(chunk)
                        if count > MAX_INSTALLER_BYTES:
                            raise AgentSelfUpdateError("Agent installer exceeds the download limit")
                        output.write(chunk)
            if temporary.stat().st_size < 2:
                raise AgentSelfUpdateError("downloaded Agent installer is empty")
            with temporary.open("rb") as payload:
                if payload.read(2) != b"MZ":
                    raise AgentSelfUpdateError("downloaded Agent installer is not a Windows executable")
            temporary.replace(destination)
            return destination
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def launch_installer(self, installer: Path) -> None:
        if os.name != "nt":
            raise AgentSelfUpdateError("Agent installer launch is supported only on Windows")
        log_path = self.state_root / "installer.log"
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen(
            [
                str(installer),
                "/VERYSILENT",
                "/SUPPRESSMSGBOXES",
                "/NORESTART",
                f"/LOG={log_path}",
            ],
            close_fds=True,
            creationflags=flags,
        )

    def poll_once(self) -> str:
        """Check, notify the active user, and hand an accepted update to the installer."""
        offer = self.check()
        if offer is None:
            return "up_to_date"
        if not offer.required and self._suppressed(offer):
            return "suppressed"
        outcome = self.prompt(offer)
        if outcome == "later" and not offer.required:
            self._suppress(offer)
            return "later"
        installer = self.download(offer)
        self.launch_installer(installer)
        return "update_started"
