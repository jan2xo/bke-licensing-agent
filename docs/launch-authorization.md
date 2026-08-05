# Launch Authorization

`AuthorizationService` returns a typed decision and never launches a product.
Authorization requires a validated manifest and a verified lease matching the
installation, device, product, and version. Expired, future, mismatched, or
invalid state fails closed.
