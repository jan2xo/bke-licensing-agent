# Session lifecycle

```text
login -> validate credentials -> store token pair in OS keyring
  |
  +-> current session -> validate with server when requested
  |
  +-> refresh -> replace stored token pair under a lock
  |
  +-> logout -> revoke remotely when possible -> delete local keyring entry
```

Missing, expired, revoked, or corrupted state is not treated as authenticated.
Logout clears in-memory state immediately after the remote request and secure
storage deletion path is invoked. The session manager never decides whether an
application may launch.

Refresh is due when the stored access-token expiration is within
`ApiConfig.refresh_threshold`; `AuthenticationService.ensure_fresh_session()`
then performs the refresh. Explicit `refresh_session()` always requests a
refresh. Logout, revocation, or session replacement permanently invalidates all
refresh operations created under an earlier session generation.
