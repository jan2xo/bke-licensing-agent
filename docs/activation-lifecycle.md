# Activation lifecycle

```text
authenticated session -> installation identity -> hashed fingerprint
-> device registration -> product entitlement -> activation -> verification
-> non-sensitive local cache
```

Activation and device registration are serialized within the licensing service.
Non-idempotent operations are not retried by the API client. The service does
not launch applications or authorize offline use.
