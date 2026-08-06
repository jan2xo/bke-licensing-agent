from bke_licensing_agent.platforms import PackagingTarget


def test_packaging_targets_are_explicit_and_platform_neutral():
    assert {item.value for item in PackagingTarget} == {
        "macos-arm64", "macos-x64", "linux-x64", "linux-arm64",
        "windows-x64", "windows-arm64",
    }
