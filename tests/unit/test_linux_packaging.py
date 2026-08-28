from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_linux_deb_stops_before_replace_and_preserves_enablement_on_upgrade():
    source = (ROOT / "packaging" / "linux" / "build-deb.sh").read_text(encoding="utf-8")

    assert 'cat > "$STAGE/DEBIAN/preinst"' in source
    assert "systemctl stop bke-licensing-agent.service" in source
    assert "systemctl is-active --quiet bke-licensing-agent.service" in source
    assert "systemctl enable bke-licensing-agent.service" in source
    assert "systemctl restart bke-licensing-agent.service" in source
    assert "remove|deconfigure" in source
    assert "upgrade)" in source


def test_linux_upgrade_notes_remain_explicitly_uncertified():
    notes = (ROOT / "packaging" / "linux" / "UPGRADE-NOTES.md").read_text(encoding="utf-8")

    assert "NOT LIVE-CERTIFIED" in notes
    assert "Do not report Linux in-place upgrade as certified" in notes
