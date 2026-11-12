# BKE machine-key exchange certification plan — SOURCE DRAFT

Master ledger: https://github.com/jan2xo/bke-digital-solutions/issues/340

Intent: authenticated Agent private-key public enrollment, DS-issued one-time ENROLL challenge, exact signature verification, and authenticated revocation. LEASE issuance remains private / unsupported externally until an entitlement-checked transactional JWS signer exists.

Source parent: `06d8109f31cb92afc6fff2db1872e4782846b784` (upstream draft; not merged).

Security: DS authenticates an existing Agent bearer, validates version/Origin, applies distributed fail-closed IP and token-scoped limits before DB writes; strict bounded payloads; executes existing key authority under SERIALIZABLE; produces only public key/challenge/verification state; no secrets or trusted proof material exposed. Agent securely carries token, verifies DS challenge envelope via local protected key, refuses redirect, inconsistent signed context, malformed responses and untrusted servers.

DS required graph: pr core licensing native-account identity prisma-isolation (with DB/migrations, cloud runtime, security; include entitlement/catalog only if behavior changes). Agent required graph: contracts windows-x64 for real protected key signing and simulated route transport; include exact immutable upstream SHA source-check in tests.

Not required: commerce/payments, package publishing, installer lifecycle, UTM/VM, Launcher, Render Dock, live prod route, JWS signing, product execution.

No merge while dependent draft source remains unmerged. Production, release, migration, signing cutover locked.