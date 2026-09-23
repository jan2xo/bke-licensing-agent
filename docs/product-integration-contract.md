# Product integration contract

A product joins BKE software management with a trusted local `bke.manifest.json`
plus a signed BKE install-target policy.

## Product manifest

The local product manifest remains:

- schema: `bke.product.v1`
- product_id
- version
- platform
- architecture
- executable relative to install_root
- install_root
- update_channel
- optional local health-check identity

The product talks only to the Agent localhost capability boundary. It does not
contain Digital Solutions credentials, release trust keys, or cloud licensing
authority.

## Signed install-target policy

`bke.install-target-policy.v1` remains valid for install/update compatibility,
but it carries no uninstall authority.

New managed installations should use
`bke.install-target-policy.v2`, which adds a signed `uninstall` declaration.

Supported uninstall strategies:

### MANAGED_DIRECTORY

Use only when BKE itself provisioned the product from a verified managed package
and the product has no external installer bookkeeping.

```json
{
  "strategy": "MANAGED_DIRECTORY"
}
```

The Agent may remove only the verified product install root recorded with
`BKE_MANAGED_PACKAGE` provenance.

### INSTALLER_EXECUTABLE

Use when a trusted product installer owns machine integration such as shortcuts,
services, registry entries, or installer bookkeeping.

```json
{
  "strategy": "INSTALLER_EXECUTABLE",
  "executable": "unins000.exe",
  "arguments": ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
}
```

The executable must be a safe relative path under the verified install root.
Arguments are signed as part of the target policy. The Agent executes exactly
the recorded/signed command, waits for completion, verifies the product entry
point disappeared, and only then clears local inventory.

## Installation provenance

Removal authority is per installed instance, not merely per product ID:

- `BKE_MANAGED_PACKAGE` + `MANAGED_DIRECTORY` → managed-root removal allowed.
- `PRODUCT_INSTALLER` + `INSTALLER_EXECUTABLE` → product uninstaller required.
- `LEGACY_UNKNOWN` or `NONE` → destructive removal refused.

Existing inventory rows migrate to `LEGACY_UNKNOWN` / `NONE`. The Agent must
never guess that an old/manual installation is safe to delete.

For Render Dock specifically, the BKE first-install flow consumes the verified
`.update.zip`, so that instance is BKE-managed and may use
`MANAGED_DIRECTORY`. A separately installed Inno Setup copy must use its
installer-owned uninstall mechanism if/when it is explicitly registered with
`PRODUCT_INSTALLER` provenance.

User-created projects, exports, and other data outside the signed install root
are not removal targets.

Authorization mapping remains:

- UP_TO_DATE and UPDATE_AVAILABLE: ALLOW
- UPDATE_REQUIRED: continue only while the Agent's explicit offline policy permits; otherwise DENY
- UNSUPPORTED or unverifiable policy: DENY

AirStack, RenderDock, Scraper, WeatherWatch desktop components, WPF/.NET
applications, and Python applications use the same capability contract. Their
package layout and uninstall strategy may differ; BKE and the Agent do not
hardcode product-specific uninstall commands.
