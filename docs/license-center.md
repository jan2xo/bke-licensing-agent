# BKE License Center

The License Center is a thin customer-facing companion interface. It delegates
connect, authentication, discovery, activation, status, deactivation, logout,
and return-to-product actions to the Licensing Agent boundary. It does
not verify leases, store credentials, or implement licensing policy.

The Tk presentation masks license-key input, disables activation while the
request is active, closes after success, and leaves the error screen available
for retry after failure.

The presentation accepts the product-agnostic `activate_license` mode. In that
mode it displays replacement context and preserves the current authorization
until the new candidate has been verified and persisted.

Future products integrate through the typed `OpenLicenseCenterRequest` and
`LicenseCenterAction` contract. Demo keyboard shortcuts are certification-only
and are translated internally before reaching the Agent service.

The reference Demo Product constructs this controller automatically. On a
fresh installation it opens the window after `activation_required`; after a
successful activation, the existing Licensing Agent lease-metadata repository
is used on the next launch. Metadata is cache-only: the current signed lease
is retrieved from the platform and verified again before authorization.
