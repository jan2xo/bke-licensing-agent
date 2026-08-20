# Universal Updater Remediation Certification

Final certification-world evidence, 2026-08-20.

## Immutable dependency

Agent certification consumes updater-core commit:

`3b25e6abe50e35a356a2130166292889f9b4fd94`

All Agent CI and cross-repository workflow checkout references use this SHA. The obsolete top-level helper package was removed; tests exercise the packaged helper.

## Executed results

- Updater Core CI: PASS — run 32385840726.
- Licensing Agent CI: PASS — run 32385871166.
- Cross-repository certification: PASS — run 32385871184.
- Digital Solutions authority HTTP lifecycle: PASS.
- Executable updater certification: PASS.
- Real broken-Agent external-helper rollback: PASS.
- Durable post-restart transaction reconciliation: PASS.

## Broken Agent lifecycle

A real Agent subprocess persisted the self-update transaction, launched the packaged helper, passed its PID, and terminated. The helper detected termination, replaced the installation with a deliberately failing Agent B, observed startup failure, restored Agent A, launched the restored executable, and persisted `ROLLED_BACK`. A fresh Agent-side read after the subprocess completed observed the durable terminal state.

The test does not mock PID termination, helper launch, replacement, startup, or health. Readiness requires a flushed signal and post-readiness process liveness; rollback relaunches Agent A inside the helper.

## Scope

The compiled fixture certification is a generic executable fixture lifecycle. It is not a claim of Windows/WPF production certification. No production or VPS resources, keys, licenses, or customer data were used.
