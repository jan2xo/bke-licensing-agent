# Device identity

`InstallationIdentity` creates a random installation identifier on first use
and stores it through the Phase 4 secure credential-store abstraction. It is
distinct from the server device ID and can only be changed through explicit
reset. Corrupt stored identity fails closed.
