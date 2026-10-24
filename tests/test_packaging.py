# -*- coding: utf-8 -*-
"""打包入口与版本号契约测试。

只验证「入口可用、版本一致、spec 存在」；不实际运行 PyInstaller（构建慢且依赖环境）。
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

import netopt
from netopt import _FALLBACK_VERSION

ROOT = Path(__file__).resolve().parent.parent


def test_version_is_single_source() -> None:
    """`netopt.__version__` 与 `VERSION` 一致，且非空。"""
    assert netopt.__version__
    assert netopt.__version__ == netopt.VERSION


def test_version_matches_pyproject() -> None:
    """源码树运行时的版本号必须与 pyproject 的发布版本一致。"""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert netopt.__version__ == data["project"]["version"]


def test_fallback_version_matches_pyproject() -> None:
    """冻结产物读不到元数据时用的内置回退版本，也必须与 pyproject 一致。"""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == _FALLBACK_VERSION


def test_python_m_netopt_version() -> None:
    """`python -m netopt version` 能启动并打印版本号。"""
    proc = subprocess.run(
        [sys.executable, "-m", "netopt", "version"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert netopt.__version__ in proc.stdout


def test_source_version_wins_over_stale_metadata(tmp_path: Path) -> None:
    """源码树运行时，环境里残留的旧版 dist-info 不得覆盖 pyproject 版本。"""
    dist_info = tmp_path / "net_optimizer-1.1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: net-optimizer\nVersion: 1.1.0\n",
        encoding="utf-8",
    )

    env = {**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONUTF8": "1"}
    proc = subprocess.run(
        [sys.executable, "-c", "import netopt; print(netopt.__version__)"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    # 旧 dist-info 的 1.1.0 必须被忽略，取源码树 pyproject 的发布版本
    assert proc.stdout.strip() == netopt.__version__


def test_pyinstaller_specs_exist() -> None:
    """两份 spec 都存在，且产物名正确。"""
    cli_spec = (ROOT / "packaging" / "netopt.spec").read_text(encoding="utf-8")
    gui_spec = (ROOT / "packaging" / "netopt-gui.spec").read_text(encoding="utf-8")
    assert 'name="netopt"' in cli_spec
    assert "console=True" in cli_spec
    assert 'name="NetOptimizer"' in gui_spec
    assert "console=False" in gui_spec
