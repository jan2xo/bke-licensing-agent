# Licensing platform API contract

Phase 3 provides a typed, product-agnostic HTTPS client foundation. The
configured platform is the authority for products, licenses, devices, and
verification results.

Supported client operations are `GET /health`, `GET /products/{product_id}`,
`GET /licenses/{license_id}`, `POST /devices`, and `POST /licenses/verify`.
Responses are validated with Pydantic models. The endpoint paths are client
contract placeholders and do not claim that a production server currently
implements them.

The client requires HTTPS outside explicitly enabled `local` or `test`
environments. It applies connect/read timeouts, request IDs, bounded retries
for idempotent requests, and redacted user-facing errors. Device registration
and license verification are not automatically retried because they are
non-idempotent until the platform supplies an idempotency-key contract.

This phase does not implement authentication, token storage, activation
persistence, offline authorization, or launch permission.
