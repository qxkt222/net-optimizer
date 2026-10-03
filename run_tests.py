#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""net-optimizer 本地门禁。

用法::

    python run_tests.py           # 全量门禁
    python run_tests.py --fast    # 只跑 import 冒烟 + pytest

门禁项（任一项失败则整体失败）::

    1. import 冒烟   —— 每个模块能独立 import（GUI 除外，它需要显示器）
    2. ruff check    —— lint
    3. ruff format   —— 格式检查（不自动改文件）
    4. pytest        —— 单元测试

刻意不做的事：不自动修格式、不装依赖、不联网。
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# 本机是 cp936 locale，而 site-packages 里 pdbpp 的 `_pdbpp_path_hack/pdb.py`
# 会用默认编码（GBK）去 exec 标准库 pdb.py，直接 UnicodeDecodeError →
# pytest 启动即 INTERNALERROR。给子进程强制 UTF-8 模式绕开，别指望用户记得加。
CHILD_ENV = {**os.environ, "PYTHONUTF8": "1"}

SMOKE_MODULES = [
    "netopt",
    "netopt.models",
    "netopt.ui",
    "netopt.platform",
    "netopt.parsers",
    "netopt.probes",
    "netopt.state",
    "netopt.diag",
    "netopt.fix",
    "netopt.health",
]


def _enable_utf8_console() -> None:
    """控制台是 cp936，直接打印中文会乱码。

    必须**同时**切控制台代码页和 Python 流的编码：只 reconfigure 流会让
    终端按 GBK 解释 UTF-8 字节，反而更花。
    """
    with contextlib.suppress(Exception):  # 非 Windows / 无控制台时静默跳过
        import ctypes

        k = ctypes.windll.kernel32
        k.SetConsoleOutputCP(65001)
        k.SetConsoleCP(65001)
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(encoding="utf-8", errors="replace")


def _say(step: str, ok: bool, detail: str = "") -> bool:
    mark = "PASS" if ok else "FAIL"
    line = f"[{mark}] {step}"
    if detail:
        line += f"  {detail}"
    print(line, flush=True)
    return ok


def step_smoke() -> bool:
    """每个模块能独立 import —— 抓循环导入、语法错误、顶层副作用。"""
    sys.path.insert(0, str(ROOT))
    bad: list[str] = []
    for name in SMOKE_MODULES:
        try:
            importlib.import_module(name)
        except Exception as exc:  # 冒烟就是要抓一切
            bad.append(f"{name}: {type(exc).__name__}: {exc}")
    return _say("import 冒烟", not bad, "; ".join(bad))


def _run_tool(argv: list[str]) -> tuple[bool, str]:
    exe = shutil.which(argv[0])
    if exe is None:
        return False, f"找不到 {argv[0]}（跳过或先安装）"
    p = subprocess.run(
        [exe, *argv[1:]],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        errors="replace",
        env=CHILD_ENV,
    )
    return p.returncode == 0, (p.stdout + p.stderr).strip()


def step_ruff_check() -> bool:
    ok, out = _run_tool(["ruff", "check", "."])
    return _say("ruff check", ok, "" if ok else "\n" + out)


def step_ruff_format() -> bool:
    ok, out = _run_tool(["ruff", "format", "--check", "."])
    return _say("ruff format", ok, "" if ok else "\n" + out)


def step_pytest(extra: list[str]) -> bool:
    argv = [sys.executable, "-m", "pytest", *extra]
    p = subprocess.run(
        argv,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        errors="replace",
        env=CHILD_ENV,
    )
    out = (p.stdout + p.stderr).strip()
    lines = out.splitlines()
    detail = lines[-1] if (p.returncode == 0 and lines) else "\n" + "\n".join(lines[-20:])
    return _say("pytest", p.returncode == 0, detail)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="跳过 ruff，只跑冒烟和测试")
    args, extra = ap.parse_known_args()  # 不认识的参数透传给 pytest

    _enable_utf8_console()
    print(f"net-optimizer 门禁  (root={ROOT})\n" + "-" * 56)
    results = [step_smoke()]
    if not args.fast:
        results.append(step_ruff_check())
        results.append(step_ruff_format())
    results.append(step_pytest(extra))
    print("-" * 56)
    passed, total = sum(results), len(results)
    print(f"{passed}/{total} 项通过")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
