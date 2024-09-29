# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

a = Analysis(
    ['Ui_MainWindow.py', 'ExternalDataTab.py', 'DeviceManagementTab.py', 'OperationLogTab.py', 'PrintingParamsTab.py','utils.py',],
    pathex=['C:/Users/aazik/Desktop/PIJ/PIJ'],
    binaries=[],
    datas=[('resources/translations.xlsx', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PIJ Control System',
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
)
