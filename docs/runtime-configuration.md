# Runtime Configuration

The installed Agent owns one canonical runtime environment file:

```text
C:\ProgramData\BKE Digital Solutions\Licensing Agent\.env
```

The .NET Host loads this file before storage initialization, port parsing, dependency
composition, or construction of remote Digital Solutions clients. Values from this
file override process-level values of the same name so machine runtime behavior is
deterministic.

The installer owns `BKE_AGENT_DATA_DIR`; that variable is intentionally rejected
inside the Agent `.env`.

Supported environment identities are:

- `production`
- `utm`
- `development`
- `certification`

For backward compatibility, an installation with no Agent `.env` and no
`BKE_ENVIRONMENT` continues to resolve as `production`.

## UTM isolation

UTM must be explicit:

```dotenv
BKE_ENVIRONMENT=utm
BKE_PLATFORM_BASE_URL=https://<disposable-digital-solutions>
```

When `BKE_ENVIRONMENT=utm`:

- `BKE_PLATFORM_BASE_URL` is mandatory.
- `jl-bke.com` and every `*.jl-bke.com` authority are rejected at Host startup.
- A malformed platform URL is rejected before the Agent local API starts.
- HTTP remains allowed only for explicit loopback certification with
  `BKE_AGENT_VNEXT_ALLOW_INSECURE_LOCAL=1`.

The UTM helper
`certification/utm/Prepare-BkeAgent-UtmEnvironment.ps1` writes the canonical
ProgramData `.env` before the Windows installer starts the service. It refuses a
production authority and refuses non-loopback HTTP.

The Agent `.env` is machine configuration, not a cloud-secret store. Account
session secrets continue to be protected by the Agent-owned secure store.

## Production authority

The production platform authority remains `https://jl-bke.com`. After disposable
UTM certification, production should use its own explicit Agent `.env`; production
credentials and Digital Solutions secrets do not belong in the Agent configuration.
