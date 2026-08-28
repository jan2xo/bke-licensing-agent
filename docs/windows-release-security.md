# Windows Release Security and Customer Distribution Gate

Status: Approved release policy
Owner: BKE Digital Solutions

## Purpose

A successful build or CI run is not, by itself, sufficient evidence that a Windows installer is safe for customer distribution. BKE separates build certification, malware scanning, provenance, update authority, and operating-system publisher trust into explicit gates.

## Release evidence required for every Windows candidate

Every Windows release candidate must preserve the following evidence for the exact installer bytes:

1. Exact Git source commit SHA.
2. Passing BKE Licensing Agent test and packaging gates.
3. Passing RC3-to-candidate in-place upgrade certification while that migration remains relevant.
4. Passing candidate-to-candidate graceful in-place upgrade certification.
5. SHA-256 digest of the installer.
6. GitHub build-provenance attestation for the installer.
7. Microsoft Defender custom scan of the frozen Windows payload and final installer with a clean result.
8. Recorded Authenticode status and signer identity.
9. Proprietary BKE license embedded in the installer and installed payload.

## Customer distribution gate

A release candidate is NOT approved for customer production distribution unless all of the following are true:

- Authenticode verification reports `Valid` for the approved BKE publisher certificate.
- The installer and relevant executable payloads are signed through the controlled BKE signing process.
- The signing certificate private key is held through an approved protected secret or signing service and is never committed to the repository or included in build artifacts.
- The installer still matches its published SHA-256 and build-provenance record after signing.
- Production updater target trust uses persistent BKE-controlled signing keys and signed policies, not disposable CI or RC trust.
- Required Windows installation and in-place-upgrade acceptance gates are green for the exact release source.

If any of those conditions is missing, the artifact may be used for BKE engineering, certification, or controlled testing only. It must not be described as a trusted production installer.

## Microsoft Defender gate

The Windows release-candidate workflow must fail closed if Microsoft Defender scanning cannot run or reports a non-zero scan result for either:

- the frozen Windows payload directory; or
- the final Inno Setup installer.

The workflow publishes `DEFENDER-SCAN.txt` with scanner/signature information and scan exit codes alongside the installer artifact.

A Defender-clean result is a malware-screening signal. It does not replace Authenticode signing and it does not guarantee that all possible malware is detectable.

## Authenticode gate

The workflow publishes `SIGNATURE.txt` containing the Windows Authenticode status and signer identity of the final installer.

For engineering RCs, that record may state `NotSigned` and the artifact remains non-production.

For customer releases, `NotSigned`, `UnknownError`, `HashMismatch`, `NotTrusted`, or any other non-`Valid` result is a hard failure.

Do not use self-signed or disposable certificates to represent a customer release as trusted. A production release requires the approved BKE code-signing identity.

## Proprietary licensing

BKE Licensing Agent is proprietary software. The repository `LICENSE` is the canonical BKE-authored software license. Public visibility of source or release artifacts does not grant permission to copy, modify, redistribute, sublicense, or create derivative works beyond the rights expressly stated in that license.

Third-party components remain governed by their own licenses. BKE's proprietary license does not override rights BKE does not own.

## Linux status

Linux packaging may follow the same state-preserving upgrade philosophy, but Linux remains NOT LIVE-CERTIFIED until a separate Linux acceptance program is completed. Linux packaging success must not be presented as equivalent to the Windows or macOS live upgrade certification record.
