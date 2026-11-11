# Signed product lease — fraction-to-fraction interoperability

**Owner:** Licensing Agent contract certification, in the Digital Solutions #340 licensing program.

**Intent:** Use the real TypeScript `@bke/licensing` Ed25519 issuer and the Agent's real standalone .NET verifier over the identical signed JWS bytes. Prove accept/reject vectors without DS server, a production license, product installer, or machine-key custody.

**Upstream:** `jan2xo/bke-libraries-typescript` PR #90, pinned library SHA `03dfbbae3a5e4acc95b82e323940555d85cdcf42`, 14-vector stdout SHA-256 `1e4fefe9df64dd2b0313a7b127c850417659a092647e515411a6595900802d80`.

**Initial Agent base:** `e41cf1f2d69378f9ff326bab2a85dc7ba26dea1f`. **Current certification:** NOT RUN.

**Planned required:** Agent `contracts` (source compilation/compatibility) and explicit `fraction-lease` (actual TypeScript signer to .NET verifier). **Not required:** windows-x64 native payload, acquisition, rollback, installer, self-update, UTM, DS/Launcher/product CI: no privileged launch/install/production behavior changed.

**No release/merge:** This is an experimental draft against an unmerged library candidate, not an immutable released dependency. No production deployment, DB, secrets, OAuth, PayMongo, Resend, installer, catalog or signing cutover.

**Result definition:** All 14 pinned synthetic vectors have the expected decision and exact failure code; extra real signer tests pass; no unexpected acceptances/skips; exact upstream/downstream SHAs and evidence manifest match. The final PR checkpoint will replace this provisional plan with the true exact head and actual CI result.
