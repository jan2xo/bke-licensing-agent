# Phase 7 Execution Pipeline

Validated manifest and current typed authorization are bound to trusted artifact metadata. The service canonicalizes the declared entry point, verifies containment and SHA-256 integrity, rechecks generations, and invokes `subprocess.Popen` with `shell=False`.
