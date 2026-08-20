# Universal Updater Remediation Certification

Final certification-world evidence, 2026-08-20.

## Immutable dependency

Agent certification consumes updater-core commit:

`c035fd3db8cb86acdb6dda5cc86bfd0903e49996`

All Agent CI and cross-repository workflow checkout references use this SHA. The obsolete top-level helper package was removed; tests exercise the packaged helper.

## Executed results

- Updater Core CI: PASS — run 32373726202.
- Licensing Agent CI: PASS — run 32373928724.
- Cross-repository certification: PASS — run 32373928714.
- Digital Solutions authority HTTP lifecycle: PASS.
- Executable updater certification: PASS.
- Real broken-Agent external-helper rollback: PASS.
- Durable post-restart transaction reconciliation: PASS.

## Broken Agent lifecycle

A real Agent subprocess persisted the self-update transaction, launched the packaged helper, passed its PID, and terminated. The helper detected termination, replaced the installation with a deliberately failing Agent B, observed startup failure, restored Agent A, launched the restored executable, and persisted `ROLLED_BACK`. A fresh Agent-side read after the subprocess completed observed the durable terminal state.

The test does not mock PID termination, helper launch, replacement, startup, or health.

## Scope

The compiled fixture certification is a generic executable fixture lifecycle. It is not a claim of Windows/WPF production certification. No production or VPS resources, keys, licenses, or customer data were used.
