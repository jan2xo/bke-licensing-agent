# Agent runtime bridge status

This branch proves a language-independent BKE Licensing Agent machine boundary without changing production release authority.

## Stable machine contract

- Windows service: `BKE-Licensing-Agent`
- Stable SCM executable: `service\\bke-licensing-agent-service.exe`
- Replaceable runtime payload: `runtime\\bke-licensing-agent-runtime.exe`
- Durable machine state: `%ProgramData%\\BKE Digital Solutions\\Licensing Agent`
- Local API: `127.0.0.1:43873`

The bootstrap owns process supervision and Agent-release polling. The .NET 10 runtime owns licensing capabilities. The stable machine contract remains implementation-separated so service/runtime replacement stays transactional, but the current supported Agent implementation is .NET 10.

## Certification and canonical-installer boundaries

The Phase 5–7 bridge installers remain certification-only artifacts:

- `packaging/windows/bke-licensing-agent-runtime-bridge.iss`
- `packaging/windows/bke-licensing-agent-runtime-bridge-arm64.iss`

Their `bridge-cert.enable` marker now serves only as a certification self-update suppressor.

Phase 8 migrates the canonical Windows installer definitions on the stacked candidate branch:

- `packaging/windows/bke-licensing-agent.iss` → native Gen2 x64
- `packaging/windows/bke-licensing-agent-arm64.iss` → native Gen2 ARM64

Canonical installers delete any stale `bridge-cert.enable` marker and never create one. After the certified Phase 8–10 waves, the License Center, updater helper, privileged provisioner, and release tooling were migrated to native .NET 10. Python/PyInstaller is no longer an active packaging/runtime dependency.


## Post-certification .NET-only convergence

After Phases 8–10 passed, the active Agent tree was converged to .NET 10-only execution and build tooling. Historical Python migration evidence remains preserved in Git history and the cited workflow runs, but the current branch no longer ships or builds the Python runtime.

Current Windows executable set:

```text
service\\bke-licensing-agent-service.exe
runtime\\bke-licensing-agent-runtime.exe
license-center\\bke-license-center.exe
updater\\bke-updater-core.exe
provisioning\\bke-privileged-provisioner.exe
```

All are built natively for x64/AMD64 and ARM64. The post-certification .NET-only convergence has now passed both hosted x64 acceptance and persistent Windows 11 ARM64 acceptance.

## Phase 8 hosted result

GitHub Actions workflow `.github/workflows/dotnet-production-installer.yml` first passed the executable migration candidate at `f71f5cd1444f68027d15510f243151ea99a8190c`; the final PowerShell 5.1-safe Phase 8 head `1ec04a603eaa913e452ca9389b164ee25be4bdfe` also passed hosted replay run `35371763991`.

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

## Phase 8 final acceptance — CLOSED

Phase 8 is formally closed.

The PowerShell 5.1-safe certification-script fix at `1ec04a603eaa913e452ca9389b164ee25be4bdfe` passed the hosted production-installer workflow:

```text
run: 35371763991
result: SUCCESS
```

The persistent Windows 11 ARM64 UTM machine `WIN-J2SML1QDPBD` then completed the canonical ARM64 installer acceptance with:

```text
schema: bke.production-installer-arm64.v1
status: PASS
installer_exit_code: 0
installer_sha256: df00858459d58c36b270999f3dad784998eceae4d6864210b1a34579dc30d1cb
```

Every machine acceptance check passed:

- installer identity preserved
- service running
- stable SCM identity preserved
- canonical assets present
- native ARM64 service/runtime payloads
- certification marker removed
- successful-install rollback staging discarded
- durable ProgramData state preserved
- signed authorization recovered
- runtime supervision recovered
- port 43873 remained loopback-only and owned by the Gen2 runtime
- machine data-root contract preserved

Resulting machine hashes:

```text
service:
f119486c5bf0b98b636a3291a638a71ff9762a7b8f5c7c5390c16bc424cc689e

runtime:
fb7799db6dec72c45d2c0ef10fad91ba744296f0c1c778c2088bdfbc4a212610

agent.db:
e00994231d220e1d671d99986a353badb3062ba237ae9cb2fb069c8580cd7ed5
```

Stable SCM executable after migration:

```text
C:\Program Files\BKE Digital Solutions\Licensing Agent\service\bke-licensing-agent-service.exe
```

Phase 8 therefore proves the canonical Windows Gen2 installer migration on hosted x64 and the persistent native ARM64 machine.

Production signing, production catalog/update-authority publication, release/tag creation, deployment, and merges remain unauthorized. Production-signed self-update is Phase 9; broken production update rollback remains Phase 10.


## Phase 9 signed self-update pre-publication certification — CLOSED

Phase 9 pre-publication certification is formally closed.

Exact Agent head:

```text
83c0c8208e06cbd4f554092c3c2ec28d8d2bf149
```

Pinned BKE Digital Solutions V2 authority:

```text
edfee191b25815cd58ea8d7a5fc8741e6f08865b
```

The final Phase 9 proof established:

- Ed25519-signed `bke.update-policy.v1` authority
- exact product/version/platform/architecture binding
- deterministic release and asset identity
- monotonic signed authority revisions
- signed installer SHA-256 and byte-length binding
- rejection of unknown keys, invalid signatures, stale revisions, extra fields, architecture drift, version rollback, and tampered installer bytes
- catalog URL derivation from signed release/asset identity rather than an arbitrary server-provided URL
- public update-authority keys only in the canonical Windows installer trust bundle
- independent Node/V2 authority -> .NET Agent signature verification for x86_64 and ARM64
- successful native x64 and ARM64 bootstrap publication with the verifier
- successful canonical production-installer regression replay

Exact-head successful runs included:

```text
35374567805  CI push
35374567823  Phase 9 signed Agent self-update push
35374571656  CI PR
35374571382  Cross-repository updater certification
35374571374  .NET 10 Agent Gen2
35374571467  .NET 10 Agent vNext
35374571379  Phase 9 signed Agent self-update PR
35374571378  production-installer regression
```

Disposable signed-policy evidence:

```text
artifact id: 10559498643
digest: sha256:a06be14eb966bc10d3b1cd259bcfa79442640813488d53907da1839fe958c9bb
```

Phase 9 did **not** create or activate a production signing key, publish a production software-catalog release, deploy the V2 authority, or perform production cutover.

## Phase 10 broken-update rollback certification — CLOSED

Phase 10 is formally closed.

Hosted Windows x64 certification first proved that a deliberately broken 2.0.1 runtime installed through the canonical installer fails the replacement health gate and automatically restores the prior healthy 2.0.0 service/runtime byte-for-byte.

Hosted rollback proof:

```text
schema: bke.broken-update-rollback.v1
status: PASS
baseline_version: 2.0.0
rejected_version: 2.0.1
```

Final combined hosted run:

```text
35376355971
result: SUCCESS
```

That run also validated the ARM64 verifier, published native ARM64 broken-update payloads, verified PE machine `0xAA64`, passed Microsoft Defender scanning, and assembled the persistent-UTM acceptance kit.

The persistent Windows 11 ARM64 UTM machine `WIN-J2SML1QDPBD` then completed the real broken-update rollback proof.

Prepare baseline:

```text
installer_sha256:
fd4cb0b23639ab36120a17dc008bcd72014a038fd262b875d668c73158cdc75c

baseline_service_sha256:
f119486c5bf0b98b636a3291a638a71ff9762a7b8f5c7c5390c16bc424cc689e

baseline_runtime_sha256:
fb7799db6dec72c45d2c0ef10fad91ba744296f0c1c778c2088bdfbc4a212610
```

Final real-machine result:

```text
schema: bke.broken-update-rollback-arm64.v1
status: PASS
installer_exit_code: 0
```

Every ARM64 rollback check passed:

- installer identity preserved
- installer exited zero
- rollback log confirmed
- service running
- stable SCM identity preserved
- native ARM64 payloads restored
- original service/runtime hashes restored byte-for-byte
- durable ProgramData state preserved
- durable signed authorization recovered
- rollback staging cleared
- runtime supervision recovered
- port 43873 remained loopback-only and owned by the supervised runtime
- machine data-root contract preserved

Recovered ARM64 hashes:

```text
service:
f119486c5bf0b98b636a3291a638a71ff9762a7b8f5c7c5390c16bc424cc689e

runtime:
fb7799db6dec72c45d2c0ef10fad91ba744296f0c1c778c2088bdfbc4a212610
```

Stable SCM executable after rollback:

```text
C:\Program Files\BKE Digital Solutions\Licensing Agent\service\bke-licensing-agent-service.exe
```

The first real-machine attempt exposed a verifier-only Inno log-path quoting defect because the ProgramData evidence path contains spaces. The installer itself returned exit code 0. The verifier was corrected at:

```text
e68ca0c0b317fa59f728b05bc08fc720665a21b5
```

After replacing only the verifier script from GitHub, Prepare re-established the same original 2.0.0 hashes and Install/Collect returned PASS.

Phase 10 therefore proves automatic rollback from a broken canonical Windows update on both hosted x64 and the persistent native ARM64 machine.

All merge, production deployment, production release/tag, production software-catalog publication, and production signing-key cutover guardrails remain unchanged.


## Post-certification .NET-only convergence — CLOSED

The post-certification language convergence is formally closed.

Certified software head:

```text
48716d34833fb26adc78b14069c01671687d4a0b
```

Draft convergence PR:

```text
PR #38
refactor(gen2): retire Python and converge Agent on .NET 10
```

The active repository tree at the certified head contains no Python runtime/build sources:

```text
*.py             0
*.spec           0
pyproject.toml    0
```

The canonical Windows executable set is now native .NET 10:

```text
service\\bke-licensing-agent-service.exe
runtime\\bke-licensing-agent-runtime.exe
license-center\\bke-license-center.exe
updater\\bke-updater-core.exe
provisioning\\bke-privileged-provisioner.exe
```

Hosted exact-head certification passed:

```text
35387326089  CI push                              SUCCESS
35387331217  CI PR                                SUCCESS
35387331304  Phase 9 signed self-update replay    SUCCESS
35387331231  Phase 11 release preflight           SUCCESS
35387326051  .NET-only production installer push SUCCESS
35387331411  .NET-only production installer PR   SUCCESS
35387331387  Phase 10 rollback replay             SUCCESS
```

The hosted installer proof established:

- native x64/AMD64 and ARM64 support-payload publication
- PE machine verification for service, runtime, License Center, updater, and provisioner
- canonical x64 and ARM64 installer compilation
- Microsoft Defender scanning
- fresh hosted x64 installation
- stable SCM service/runtime/API recovery
- native .NET License Center smoke
- .NET privileged updater configuration
- zero Python/PyInstaller residue under the installed Program Files tree
- successful automatic rollback from deliberately broken 2.0.1 to healthy 2.0.0 using the expanded install-root transaction

Primary hosted .NET-only artifact:

```text
artifact id: 10564438481
digest: sha256:d3570580a337fa987e071b3aa616c6dac8b8e787e066f835708a555bd0be6062
run: 35387326051
```

Phase 11 preproduction artifact:

```text
artifact id: 10564782091
digest: sha256:48dabd43b3cf294211a778cd01ab35e79dccb704eb770374915a66b71ec9010f
```

Phase 10 exact-head rollback evidence:

```text
evidence artifact id: 10564617919
digest: sha256:5d0facffa0a094152cb8946a7a474967a554e42e3c6fcea9897ecb47558ea15d

ARM64 rollback kit artifact id: 10564632795
digest: sha256:85608ba27b84df6b448a43a5eeb40afdfe63af4365759ce76797118198d42c26
```

### Persistent Windows 11 ARM64 acceptance

Machine:

```text
WIN-J2SML1QDPBD
```

Verifier:

```text
certification/windows_dotnet_only_arm64.ps1
schema: bke.dotnet-only-arm64.v1
status: PASS
verified_at: 2026-09-18T20:18:00.2028973+00:00
installer_exit_code: 0
```

Prepared installer identity:

```text
installer_sha256:
0d72a4ed6bf986394f3173203f81b662cc3bcde0c871787541d7f9336fbb07b2
```

Baseline and resulting stable service/runtime hashes matched exactly:

```text
service:
fba60eb296994d96b95dd4eedd4dc86c3669840cd2b6ad98fc6ed315f80245e0

runtime:
e4b339103f9cbbe6f31981a0cfeb7d2d48bd7e67a1d181fc769507a184a03afe
```

Native .NET support executable hashes after convergence:

```text
license-center:
a81ee8f14c948ddbffb0b1c164e5b63d380cbb829629d7b92dd93e78475b8b1a

updater:
de544defa3202f7f028476f6c5f98a349b0f0a3c008e578cf8151aebb8548aa7

provisioner:
e055248d02e9ec3c14635d199bc6fcce0108fab1b72cc2615e1f30d3fde8a8f0
```

Every real ARM64 convergence check passed:

- installer identity preserved
- installer exited zero
- service running
- stable SCM identity preserved
- all five installed executables native ARM64
- native .NET License Center smoke passed
- Python/PyInstaller runtime residue removed
- .NET privileged updater configured
- durable ProgramData state preserved
- signed authorization recovered
- runtime supervision recovered
- port 43873 loopback boundary preserved
- rollback staging cleared
- machine data-root contract preserved

Stable SCM executable after convergence:

```text
C:\Program Files\BKE Digital Solutions\Licensing Agent\service\bke-licensing-agent-service.exe
```

The .NET-only convergence is therefore certified on hosted x64/AMD64 and the persistent native Windows ARM64 machine.

Historical Python implementation and migration evidence remain available only through Git history and prior Actions runs; Python/PyInstaller is no longer an active runtime, package, test, or release-tooling dependency on the convergence branch.

Production signing, merge, production tag/release, software-catalog publication, update-authority activation, and deployment remain separate owner-controlled boundaries.
