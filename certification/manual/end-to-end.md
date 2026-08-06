# End-to-End Demo Certification (macOS)

From the repository root:

```bash
source .venv/bin/activate
python -m bke_licensing_agent scan --paths samples/bke-demo-product
python samples/bke-demo-product/demo_app.py
```

The Demo Product constructs the certification agent and License Center
automatically. Enter `BKE-DEMO-VALID`, select **Activate**, and verify the window closes only after
the signed lease has passed the existing verifier and authorization service.
The product then runs until Ctrl+C. Repeat the command and verify the existing
agent metadata is loaded and the current signed lease is retrieved and verified
again; the License Center must not reopen. Repeat with `BKE-DEMO-INVALID`, `BKE-DEMO-EXPIRED`,
`BKE-DEMO-REVOKED`, `BKE-DEMO-WRONG-PRODUCT`, `BKE-DEMO-WRONG-DEVICE`, and
`BKE-DEMO-DEVICE-LIMIT`; each must deny and must not enter RUNNING.
