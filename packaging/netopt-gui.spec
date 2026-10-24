# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec：图形界面版 NetOptimizer.exe（onefile，无控制台）。

构建（仓库根目录）::

    pyinstaller packaging/netopt-gui.spec

产物：``dist/NetOptimizer.exe``。已在 Windows 11 + Python 3.13 + PyInstaller 6.22.3
实测构建成功；tkinter / Tcl / Tk 运行库已确认打入包内，界面交互需人工验证。
"""

import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

hiddenimports = [
    "pydantic",
    "pydantic_settings",
    "rich",
    "typer",
    "httpx",
    "tkinter",
    "netopt.system.iphlpapi",
    "netopt.system.wlanapi",
]
hiddenimports += collect_submodules("pydantic")

# 与 netopt.spec 同理：把版本真值 pyproject.toml 放进包根，冻结后
# ``netopt._source_version()`` 才能读到正确版本。
datas = collect_data_files("rich") + [(os.path.join(ROOT, "pyproject.toml"), ".")]

a = Analysis(
    [os.path.join(ROOT, "gui.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 排除仅开发期使用的 pydantic v1 兼容层与 mypy 插件（理由见 netopt.spec）。
    excludes=["pydantic.v1", "pydantic.mypy"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NetOptimizer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
