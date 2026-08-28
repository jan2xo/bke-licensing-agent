from __future__ import annotations

import importlib.util
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from bke_updater_core.target_policy import TargetInstallPolicyVerifier


def _load_signer():
    path = Path(__file__).resolve().parents[2] / "scripts" / "sign_install_target_policy.py"
    spec = importlib.util.spec_from_file_location("sign_install_target_policy", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_render_dock_policy_round_trips_through_updater_core_verifier() -> None:
    signer = _load_signer()
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    unsigned = signer.build_unsigned_policy(
        policy_id="bke-render-dock-windows-x64-v1",
        revision=1,
        product_id="bke-render-dock",
        platform="windows",
        architecture="x64",
        install_root=r"C:\Program Files\BKE Digital Solutions\Render Dock",
        entry_point="RENDER DOCK.exe",
        signing_key_id="proof-render-dock-target-v1",
    )
    document = signer.sign_policy(unsigned, private_pem)

    verified = TargetInstallPolicyVerifier(
        {"proof-render-dock-target-v1": public_raw},
        approved_roots=(r"C:\Program Files\BKE Digital Solutions",),
    ).verify(document)

    assert verified.product_id == "bke-render-dock"
    assert verified.platform == "windows"
    assert verified.architecture == "x64"
    assert verified.install_root == r"C:\Program Files\BKE Digital Solutions\Render Dock"
    assert verified.entry_point == "RENDER DOCK.exe"


def test_signer_rejects_zero_revision() -> None:
    signer = _load_signer()
    try:
        signer.build_unsigned_policy(
            policy_id="bke-render-dock-windows-x64-v1",
            revision=0,
            product_id="bke-render-dock",
            platform="windows",
            architecture="x64",
            install_root=r"C:\Program Files\BKE Digital Solutions\Render Dock",
            entry_point="RENDER DOCK.exe",
            signing_key_id="proof-render-dock-target-v1",
        )
    except ValueError as exc:
        assert "revision" in str(exc)
    else:
        raise AssertionError("zero revision must fail")
