# Machine-key registration reconciliation: Agent source intent

Authority: DS issue #340 — https://github.com/jan2xo/bke-digital-solutions/issues/340
Upstream exact source head: `85b5d2f0152fce46a2a3dc6ed7b741d5a557d36c` (unmerged draft; no release activation).

**Behavioral intent:** Do not lose registration proof on restart/ambiguous enrollment response. Reconcile authenticated server registration state with a private local key + DPAPI-protected durable receipt, refuse mismatched/foreign session or corrupt key/receipt. Require remote key revocation confirmation before local key destruction / account switch, and do not silently rotate under registration conflict. Keep existing identity/entitlement/Agent runtime boundaries. Do not claim TPM or protected provenance against stolen bearer.

**Required exact-head graph:** `contracts windows-x64`. Reason: Windows DPAPI ciphertext persistence, authenticated AccountSession logout orchestration, secure remote verification and native test.
**Not required:** payments/commerce/Resend/PayMongo, installer/UTM/release/publishing, Launcher/product, JWS entitlement/signing, production.

Security blockers: stolen bearer + initial enrollment is not installation attestation. No live DS HTTP cross-runtime E2E yet. No production or merge while upstream drafts are blocked. No automation of key deletion absent explicit confirmed remote state.
