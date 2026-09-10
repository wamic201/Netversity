# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['..\\Source\\Netversity.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('..\\assets\\wifi_icon.png', '.'),
        ('..\\assets\\ethernet_icon.png', '.'),
    ],
    hiddenimports=[
        'matplotlib.backends.backend_tkagg',
    ],
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
    a.binaries,
    a.datas,
    [],
    name='Netversity',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['..\\assets\\icon.png'],
    uac_admin=True,
)
