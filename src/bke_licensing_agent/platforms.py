"""Platform-neutral packaging target definitions."""

from enum import StrEnum
import platform


class PackagingTarget(StrEnum):
    MACOS_ARM64 = "macos-arm64"
    MACOS_X64 = "macos-x64"
    LINUX_X64 = "linux-x64"
    LINUX_ARM64 = "linux-arm64"
    WINDOWS_X64 = "windows-x64"
    WINDOWS_ARM64 = "windows-arm64"


def current_target() -> PackagingTarget | None:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin":
        return PackagingTarget.MACOS_ARM64 if machine in {"arm64", "aarch64"} else PackagingTarget.MACOS_X64
    if system == "linux":
        return PackagingTarget.LINUX_ARM64 if machine in {"arm64", "aarch64"} else PackagingTarget.LINUX_X64
    if system == "windows":
        return PackagingTarget.WINDOWS_ARM64 if machine in {"arm64", "aarch64"} else PackagingTarget.WINDOWS_X64
    return None
