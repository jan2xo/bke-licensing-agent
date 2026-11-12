# Machine-key registration reconciliation: Agent source intent

Authority: DS issue #340 — https://github.com/jan2xo/bke-digital-solutions/issues/340
Upstream exact source head: `85b5d2f0152fce46a2a3dc6ed7b741d5a557d36c` (unmerged draft; no release activation).

**Behavioral intent:** Do not lose registration proof on restart/ambiguous enrollment response. Reconcile authenticated server registration state with a private local key + DPAPI-protected durable receipt, refuse mismatched/foreign session or corrupt key/receipt. Require remote key revocation confirmation before local key destruction / account switch, and do not silently rotate under registration conflict. Keep existing identity/entitlement/Agent runtime boundaries. Do not claim TPM or protected provenance against stolen bearer.

**Required exact-head graph:** `contracts windows-x64`. Reason: Windows DPAPI ciphertext persistence, authenticated AccountSession logout orchestration, secure remote verification and native test.
**Not required:** payments/commerce/Resend/PayMongo, installer/UTM/release/publishing, Launcher/product, JWS entitlement/signing, production.

Security blockers: stolen bearer + initial enrollment is not installation attestation. No live DS HTTP cross-runtime E2E yet. No production or merge while upstream drafts are blocked. No automation of key deletion absent explicit confirmed remote state.

## Cross-repository source pin

DS reconciliation owner [PR #348](https://github.com/jan2xo/bke-digital-solutions/pull/348), candidate source **`e927ab14888c1ac655a035f0b89d1ae030dcd1d5`**, stacked on certified DS #346 `a7fa8738ab8a8dc6d8642e120d2016a853cd7524`. Agent consumer parent #123 `85b5d2f0152fce46a2a3dc6ed7b741d5a557d36c`. Actual DS and Windows Agent still run in separate disposable CI, not one deployed end-to-end service. DS run for exact status source must independently PASS before any cross-repo claim.

### Source safety boundaries

- Caller supplies trusted `ActiveAccountSessionState`, not IPC body.
- DS status returns only active/pending/revoked/expired public receipt metadata after authenticated bearer; Agent matches its own DPAPI-protected SPKI thumbprint before recovery or revoke.
- A server enrollment ACK lost after activation is recovered from DS ACTIVE metadata, without second registration.
- Receipt is written in protected Windows user DPAPI with exact session/account/user/device binding, atomic create/no conflicting overwrite; corruption and identity mismatch fail closed.
- Logout hook when explicitly composed invokes server key revocation first; on failure it retains the protected Agent session and does not claim sign-out. This hook is not yet bound into installed production runtime.
- Re-enrollment after a terminal state never occurs silently; incomplete/foreign registration requires explicit recovery. Key reset cannot erase a live protected receipt.
- Not attestation, TPM, or defense against stolen Agent bearer at first enrollment.
