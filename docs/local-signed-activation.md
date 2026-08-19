# Local signed activation certification

This milestone is local/test-only. It does not use VPS credentials, production
keys, or production data.

## Automated proof

Run from the Agent repository with the disposable environment:

```bash
/tmp/bke-agent-venv/bin/pytest -q \
  tests/unit/test_local_api.py \
  tests/integration/test_platform_activation_http.py \
  tests/unit/test_license_repository.py \
  tests/unit/test_mock_platform.py \
  tests/unit/test_phase5.py \
  tests/unit/test_phase6.py
```

The HTTP integration fixture binds only to loopback, requires the `bke.licensing.v2`
header, returns a locally generated Ed25519 lease, and verifies that the Agent
persists a stable `license_id`, distinct `lease_id`, and active binding.

## Product-facing interface

`bke_licensing_agent.local_api.LocalAuthorizationServer` binds to
`127.0.0.1` and exposes only `POST /v1/authorize`. The sample product under
`samples/bke-local-product` receives only `{authorized, reason}`; it cannot read
leases, signing keys, credentials, or the Agent database.

The sample client is run with:

```bash
python samples/bke-local-product/sample_product.py \
  --agent-url http://127.0.0.1:<agent-port> \
  --installation-id <test-installation-id>
```

Before activation the expected result is `DENY`; after the Agent has a valid
active binding the expected result is `ALLOW`.

## Current boundary

The platform-side `/api/licenses/activate` route is already covered by the
Digital Solutions integration tests. The Agent HTTP test uses a disposable
local signed-response authority so it remains runnable without a Next.js,
PostgreSQL, or production environment. A full two-process Next.js-to-Agent
demo still requires a local Digital Solutions fixture seeder and is not
represented as complete by this document.

The existing refresh service still targets the legacy lease endpoint. A v2
refresh endpoint and response contract must be agreed by Digital Solutions
before refresh can be certified through the signed platform flow.
