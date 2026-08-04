# Manifest schema

Each product supplies `bke.manifest.json` beside its executable. The schema is
versioned and currently accepts schema version `1`, a stable lowercase
`productId`, a semantic `version`, supported platform and architecture values,
and a relative `entryPoint`.

The manifest identifies an installation; it is not proof of entitlement. The
agent must obtain authorization from the BKE platform before licensing actions.
Manifest paths are resolved beneath the manifest directory and are never
allowed to traverse outside it.
