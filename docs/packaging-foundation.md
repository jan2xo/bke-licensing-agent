# Cross-Platform Packaging Foundation

The Licensing Agent uses one shared Python source and protocol implementation.
Platform-specific artifacts are built separately for each operating system.

Available platform-neutral entry points are:

```text
bke-agent
bke-license-center
```

The Demo Product remains a separate consumer of the typed License Center API.
It does not embed licensing logic or access Agent storage.

Defined targets:

- `macos-arm64`
- `macos-x64`
- `linux-x64`
- `linux-arm64`
- `windows-x64`
- `windows-arm64`

The release version is `1.0.0`, sourced from
`src/bke_licensing_agent/version.py` and exposed through package metadata.
Native packaging foundations are repository-owned for all three platforms:

- macOS: PyInstaller bundles plus `packaging/macos/build-pkg.sh` and LaunchDaemon.
- Windows x64: PyInstaller bundles, a pywin32 Windows Service entry point, and
  `packaging/windows/bke-licensing-agent.iss` for Inno Setup.
- Linux amd64: PyInstaller bundles, `packaging/linux/bke-licensing-agent.service`,
  and `packaging/linux/build-deb.sh` for a Debian package.

Each service invokes `serve`, remains loopback-only on `127.0.0.1:43873`, and
keeps durable state separate from application binaries. Native installation and
reboot certification is a later release gate; hosted builds prove packaging
implementation only.

## Current-host bundle certification

The current host is `macos-arm64` (`uname -s` = `Darwin`, `uname -m` =
`arm64`). PyInstaller 6.21.0 is the selected bundler for the initial
one-directory certification bundles:

```text
dist/macos-arm64/bke-licensing-agent/
dist/macos-arm64/bke-license-center/
dist/macos-arm64/bke-demo-product/
```

The arm64 Mach-O artifacts are unsigned and are not installers. Other target
platforms remain unbuilt and unverified. The bundles were copied to a
temporary directory outside the repository and the Agent executable completed
`--help` without importing repository source.

Tk License Center operation requires a graphical session. Headless Linux
activation requires a future CLI, device-code, or local-web interface.
