# PREPRODUCTION Agent update-authority key

This procedure creates the long-lived PREPRODUCTION Ed25519 authority used only by disposable/test Digital Solutions to sign `bke.update-policy.v1` responses.

It is deliberately separate from production signing.

Generate it from a secured operator machine, **outside any Git checkout**:

```powershell
dotnet run --project .\dotnet\tools\BKE.LicensingAgent.ReleaseTooling\BKE.LicensingAgent.ReleaseTooling.csproj --configuration Release -- generate-preproduction-update-key --key-id bke-agent-update-preproduction-v1 --output-dir C:\SECURE\BKE-Agent-Update-Preproduction-v1 --authorization AUTHORIZE_OFFLINE_PREPRODUCTION_KEY_GENERATION
```

The output contains:

- `BKE-UPDATE-AUTHORITY-PRIVATE.pem` — private signing key; never commit/package/upload.
- `bke-agent-update-preproduction-v1.json` — public `bke.update-authority-key.v1` document; safe to place in the Agent PREPRODUCTION package.
- `PUBLIC-KEY-SHA256.txt` — fingerprint.
- `PREPRODUCTION-PRIVATE-KEY.txt` — custody warning.

For Digital Solutions disposable runtime, copy the private PEM and public JSON into the ignored local bundle as:

```text
.bke-disposable/signing/
  agent-update-signing-private.pem
  agent-update-signing-public.json
```

The Digital Solutions materializer verifies the pair before setting `BKE_AGENT_UPDATE_SIGNING_KEYS`.

For Agent packaging, only the public JSON may enter the build. `generate-disposable-trust` accepts:

```text
--update-key-json <path-to-public-json>
```

The packaging command validates the strict schema, key ID, Ed25519 algorithm, base64 encoding, and 32-byte public-key length before copying it into `update-authority-keys`.

This authority is PREPRODUCTION only. It must never be promoted into production configuration or a production Agent release.
