# Runtime bridge real reboot certification

This gate exists because a Windows service stop/start is not equivalent to a machine reboot.

GitHub-hosted Windows runners are disposable job VMs, so the runtime-bridge workflow must not claim a real reboot from `windows-latest`. Run this gate on a dedicated Windows certification machine after the Python -> Gen2 migration, durable-state, real-product, and rollback gates are green.

## Preconditions

The machine must contain the certification runtime bridge at the stable machine boundary:

- service: `BKE-Licensing-Agent`
- stable SCM executable: `service\bke-licensing-agent-service.exe`
- Gen2 runtime: `runtime\bke-licensing-agent-runtime.exe`
- bridge marker: `bridge-cert.enable`
- durable signed fixture: `runtime-bridge-cert` version `2.0.0`, installation `runtime-bridge-installation`

Run preparation from an elevated PowerShell session:

```powershell
powershell -ExecutionPolicy Bypass -File .\certification\windows_runtime_bridge_reboot.ps1 -Mode Prepare
```

Preparation proves authorization before reboot, snapshots the stable service/runtime hashes and SCM identity, registers a one-shot SYSTEM startup verifier, and requests a real Windows restart.

The startup verifier waits for SCM and the Gen2 child runtime, proves the Windows boot timestamp advanced, re-checks stable payload hashes and service identity, requires signed authorization to recover, confirms runtime supervision and loopback-only port 43873, then writes:

```
%ProgramData%\BKE Digital Solutions\Licensing Agent\reboot-certification\result.json
```

After the machine is back, collect the evidence:

```powershell
powershell -ExecutionPolicy Bypass -File .\certification\windows_runtime_bridge_reboot.ps1 -Mode Collect
```

A release gate is satisfied only when the result document says `"status": "PASS"`. A service restart, simulated boot, or hosted-runner replacement does not satisfy this gate.
