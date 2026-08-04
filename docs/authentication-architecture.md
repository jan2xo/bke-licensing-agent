# Authentication architecture

```text
Application
    |
    v
AuthenticationService -----> LicensingPlatformClient
    |                                  |
    v                                  v
SessionManager ---------------> HTTPS platform API
    |
    v
SecureCredentialStore -> OS keyring (Credential Manager/Keychain/Secret Service)
```

Authentication proves account identity. Licensing and launch authorization are
separate responsibilities and are not performed by these components.

`AuthenticationService` owns login, refresh, validation, and logout workflows.
`SessionManager` owns in-memory session state and token lifecycle coordination.
`KeyringCredentialStore` stores serialized token pairs through the Python
`keyring` abstraction; tokens are not written to SQLite.

The session manager uses a generation counter and condition variable. Only one
refresh is in flight for a generation; waiting callers reuse its result. Before
saving a response, the generation is checked again. Logout, revocation, or
session replacement permanently invalidates all refresh operations created
under an earlier session generation.
