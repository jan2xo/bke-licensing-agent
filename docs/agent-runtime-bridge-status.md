# Agent runtime bridge status

This branch proves a language-independent BKE Licensing Agent machine boundary without changing production release authority.

## Stable machine contract

- Windows service: `BKE-Licensing-Agent`
- Stable SCM executable: `service\\bke-licensing-agent-service.exe`
- Replaceable runtime payload: `runtime\\bke-licensing-agent-runtime.exe`
- Durable machine state: `%ProgramData%\\BKE Digital Solutions\\Licensing Agent`
- Local API: `127.0.0.1:43873`

The bootstrap owns process supervision and Agent-release polling. The runtime owns licensing capabilities. A future runtime may be .NET, Python, Rust, or another implementation as long as it preserves the runtime contract.

## Certification and canonical-installer boundaries

The Phase 5–7 bridge installers remain certification-only artifacts:

- `packaging/windows/bke-licensing-agent-runtime-bridge.iss`
- `packaging/windows/bke-licensing-agent-runtime-bridge-arm64.iss`

Their `bridge-cert.enable` marker now serves only as a certification self-update suppressor.

Phase 8 migrates the canonical Windows installer definitions on the stacked candidate branch:

- `packaging/windows/bke-licensing-agent.iss` → native Gen2 x64
- `packaging/windows/bke-licensing-agent-arm64.iss` → native Gen2 ARM64

Canonical installers delete any stale `bridge-cert.enable` marker and never create one. The existing Python/PyInstaller License Center, updater-core, privileged provisioner, and trust payload remain separate packaging boundaries.

## Phase 8 hosted result

GitHub Actions workflow `.github/workflows/dotnet-production-installer.yml` has passed for candidate head `f71f5cd1444f68027d15510f243151ea99a8190c`.

The hosted Windows proof established:

1. Windows-compatible Gen2 build/contract checks passed.
2. The exact Phase 7 Python production installer was reconstructed from `a4e7ac56547c74bd89b8a9dba43d725d771cce27`.
3. Native x64 and ARM64 service/runtime payloads published successfully.
4. PE machine checks passed for x64 and ARM64.
5. Canonical x64 and ARM64 installers compiled.
6. Microsoft Defender scanning passed.
7. The Phase 7 Python production installer installed and recovered the local API.
8. The canonical Gen2 x64 installer upgraded that installed machine in place.
9. ProgramData and `agent.db` survived the migration.
10. SCM remained `BKE-Licensing-Agent`, Automatic, LocalSystem, with the stable service executable path.
11. The stable service supervised the Gen2 runtime child.
12. Port 43873 remained loopback-only and owned by the Gen2 runtime.
13. No certification marker or successful-migration rollback staging leaked into the canonical installation.

Unsigned candidate artifact:

```text
BKE-Licensing-Agent-2.0.0-Windows-Phase8-UNSIGNED-CANDIDATES
artifact id: 10550863758
digest: sha256:b968215cf9c305a807796f891785d1a6a0728b4686876c35bc00fd32140df500
```

## Remaining Phase 8 acceptance boundary

Hosted x64 migration and native ARM64 packaging are certified, but Phase 8 is not yet formally closed.

The remaining acceptance step is to install the **canonical ARM64 Phase 8 candidate** on the persistent Windows 11 ARM64 UTM machine and verify the same installed-machine contract there. Do not disturb the already-certified machine until that explicit test is performed.

Production signing, production catalog/update-authority publication, release/tag creation, and deployment remain unauthorized. Production-signed self-update is Phase 9; broken production update rollback is Phase 10.
