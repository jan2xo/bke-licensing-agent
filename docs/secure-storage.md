# Secure credential storage

The authentication layer uses the `keyring` abstraction, which delegates to
the operating system provider where configured: Windows Credential Manager,
macOS Keychain, or Linux Secret Service.

The common interface supports save, load, and delete. Provider errors are
translated to safe authentication errors. Corrupt serialized values are
rejected. Passwords are accepted only for the duration of a login request and
are never persisted. Tokens are never stored in SQLite or emitted in logs.

If the provider is unavailable, authentication fails safely rather than
falling back to plaintext files or a database.

The selected backend is rejected when it is a null, fail, plaintext, or
zero-priority backend. Expected platform providers are Windows Credential
Manager, macOS Keychain, and Linux Secret Service through `keyring`.
