# BKE Demo Product

Minimal reference product for discovery and manual certification. It contains
no licensing logic and never emits credentials, lease contents, or signatures.

From the repository root, run:

```bash
python samples/bke-demo-product/demo_app.py
```

The product constructs the certification agent and real Tk License Center
automatically when authorization is required. After successful activation,
the Licensing Agent persists verified lease metadata; a later process loads
that metadata and retrieves/verifies the current signed lease before allowing
the product to run. The Demo Product has no separate cache.

GUI interaction is manually certified because Tk requires a desktop display;
the controller and authorization flow remain covered by automated tests.

During certification, keyboard shortcuts map to typed Agent actions:

`A` Add License, `S` Select License, `V` View Licenses, `R` Refresh License,
`D` Deactivate Device, and `Q` performs local application shutdown. Future
products must call `LicenseCenterService` with `LicenseCenterAction` values
directly; they do not use keyboard commands.
