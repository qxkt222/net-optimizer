# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec：命令行版 netopt.exe（onefile，带控制台）。

构建（仓库根目录）::

    pyinstaller packaging/netopt.spec

产物：``dist/netopt.exe``。已在 Windows 11 + Python 3.13 + PyInstaller 6.22.3
实测构建，并通过 ``version`` / ``--help`` / ``ping 127.0.0.1 --json`` 冒烟。
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
    "netopt.system.iphlpapi",
    "netopt.system.wlanapi",
]
# pydantic 的编译模型/插件在冻结后需要显式收集，否则运行期才炸。
hiddenimports += collect_submodules("pydantic")

# 冻结后 ``netopt._source_version()`` 会到包的上级目录找 pyproject.toml；
# onefile 下该目录是 ``_MEIPASS``，因此把版本真值文件一并放进包根，
# 保证 exe 的 ``version`` 不依赖源码树，也不会退化成 _FALLBACK_VERSION。
datas = collect_data_files("rich") + [(os.path.join(ROOT, "pyproject.toml"), ".")]

a = Analysis(
    [os.path.join(ROOT, "netopt", "__main__.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # pydantic 官方 hook 会 collect_submodules("pydantic")，连带 pydantic.v1
    # （拉入 hypothesis）与 pydantic.mypy（拉入整套 setuptools）。本项目只用
    # pydantic v2 运行时，二者均为开发期工具，排除后 exe 约小 2.6 MB。
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
    name="netopt",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
