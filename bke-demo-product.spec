# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['packaging/demo_entry.py'],
    pathex=['src'],
    binaries=[],
    datas=[('samples/bke-demo-product/bke.manifest.json', 'samples/bke-demo-product'), ('samples/bke-demo-product/demo_app.py', 'samples/bke-demo-product'), ('certification', 'certification')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='bke-demo-product',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='bke-demo-product',
)
