# Render Dock UTM disposable target trust

TEST ONLY. DO NOT USE THIS BUNDLE FOR PRODUCTION.

This bundle contains only public Ed25519 target keys and signed
`bke.install-target-policy.v2` documents. The signing private keys existed
only in CI process memory and were not written to the artifact. The generated Render Dock policies declare a signed `MANAGED_DIRECTORY` uninstall strategy because the BKE first-install path provisions Render Dock from its verified update ZIP rather than the standalone Inno installer.

For the Windows UTM test:

1. Install the certified BKE parent package first. The bundled Launcher and Agent are Windows x64.
2. On a Windows ARM64 guest, run that same x64 BKE stack through Windows x64 compatibility; there is no separate native ARM64 product target.
3. Open PowerShell as Administrator in this bundle directory.
4. Run:
   `powershell -ExecutionPolicy Bypass -File .\Install-RenderDock-UtmTargetTrust.ps1 -Architecture x64`
5. Run BKE and exercise the account/catalog/install flow.
6. After the test, remove the disposable trust with:
   `powershell -ExecutionPolicy Bypass -File .\Remove-RenderDock-UtmTargetTrust.ps1`

This bundle generates and installs x64 Render Dock target trust only.
