# Render Dock UTM disposable target trust

TEST ONLY. DO NOT USE THIS BUNDLE FOR PRODUCTION.

This bundle contains only public Ed25519 target keys and signed
`bke.install-target-policy.v2` documents. The signing private keys existed
only in CI process memory and were not written to the artifact. The generated Render Dock policies declare a signed `MANAGED_DIRECTORY` uninstall strategy because the BKE first-install path provisions Render Dock from its verified update ZIP rather than the standalone Inno installer.

For the Windows UTM test:

1. Install the certified BKE Licensing Agent candidate first.
2. Open PowerShell as Administrator in this bundle directory.
3. Run:
   `powershell -ExecutionPolicy Bypass -File .\Install-RenderDock-UtmTargetTrust.ps1`
4. Run the Launcher candidate and exercise the account/catalog/install flow.
5. After the test, remove the disposable trust with:
   `powershell -ExecutionPolicy Bypass -File .\Remove-RenderDock-UtmTargetTrust.ps1`

The installer auto-selects x64 or ARM64 from the guest OS architecture.
