# Windows ARM64 Real-Reboot Certification Evidence

Date: 2026-09-18

Scope: Phase 7 real reboot recovery for the Gen2 .NET runtime bridge on a persistent Windows 11 ARM64 UTM virtual machine.

## Certified source

- Branch: `feat/agent-runtime-bridge`
- Source commit used by the corrected reboot kit: `1595f48c135f6745919b53b5ac64a41537c5eac6`
- GitHub Actions run: `35342751924`
- Artifact: `BKE-Licensing-Agent-Windows-arm64-Real-Reboot-Certification-Kit`
- Artifact id: `10546690699`
- Artifact digest: `sha256:4c6aeb1e9b4d038af5128a9279cc74488cc8e4e94ec0c2f9f92d5058995f9bf9`

## Machine class

- Persistent UTM virtual machine
- Microsoft Windows 11 Home
- Windows build 26100
- Native ARM64 guest
- Gen2 service/runtime installed with the certification-only Windows ARM64 runtime-bridge installer

The machine hostname is intentionally omitted from repository evidence.

## Precondition evidence

Before the formal gate, the migrated ARM64 installation had already survived an uncontrolled real Windows reboot with:

- `BKE-Licensing-Agent` Running
- Start mode Automatic
- Service account LocalSystem
- `service\bke-licensing-agent-service.exe` present
- `runtime\bke-licensing-agent-runtime.exe` present and supervised as a child of the stable service
- local API port 43873 owned by the Gen2 runtime
- listeners limited to `127.0.0.1` and `::1`
- License Center endpoint returning HTTP 200

## Formal certification procedure

The corrected ARM64 real-reboot kit:

1. seeded disposable signed `runtime-bridge-cert` authority;
2. proved authorization through the installed Gen2 runtime;
3. recorded pre-reboot service/runtime/marker SHA-256 values and boot time;
4. registered the SYSTEM startup verifier;
5. triggered a real Windows reboot;
6. verified recovery at startup;
7. emitted `result.json`;
8. was collected with `windows_runtime_bridge_reboot.ps1 -Mode Collect`.

No Render Dock grace override was changed. No production signing authority was used.

## Result

```json
{
  "schema": "bke.runtime-bridge-reboot.v1",
  "status": "PASS",
  "checks": {
    "boot_time_advanced": true,
    "service_running": true,
    "service_identity_preserved": true,
    "payload_hashes_preserved": true,
    "durable_authorization_recovered": true,
    "runtime_supervision_recovered": true,
    "loopback_boundary_preserved": true
  },
  "error": null,
  "boot_time_before": "2026-09-18T10:36:36.1362350Z",
  "boot_time_after": "2026-09-18T12:47:34.2204470Z"
}
```

Verifier completion time:

`2026-09-18T12:47:51.1001265+00:00`

## Certification conclusion

Phase 7 — real reboot recovery — is **CLOSED / PASS** for the tested Windows 11 ARM64 migration candidate.

The evidence proves that after a real operating-system reboot:

- SCM recovered the stable service automatically;
- the service identity and startup contract remained unchanged;
- the exact certified service/runtime/marker payload hashes were preserved;
- durable signed authorization recovered;
- the stable bootstrap resumed supervision of the Gen2 runtime;
- the local API remained loopback-only.

This does not authorize production cutover by itself. Production installer migration remains a separate phase.
