#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""net-optimizer 本地门禁。

用法::

    python run_tests.py           # 全量门禁
    python run_tests.py --fast    # 只跑 import 冒烟 + pytest（不带覆盖率门槛）

门禁项（任一项失败则整体失败）::

    1. import 冒烟            —— 每个模块能独立 import（GUI 除外，它需要显示器）
    2. ruff check             —— lint
    3. ruff format --check    —— 格式检查（不自动改文件）
    4. mypy netopt            —— 静态类型
    5. tach check             —— 分层依赖方向
    6. bandit -r netopt       —— 安全扫描
    7. pytest --cov=netopt    —— 单元测试 + 覆盖率（门槛 90%）

刻意不做的事：不自动修格式、不装依赖、不联网。

外部 CLI（ruff / mypy / tach / bandit）走 ``PATH`` 查找；找不到会明确
FAIL 并提示安装，**不会静默跳过**。
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
# 同理，tach 读 pyproject.toml 时也用默认编码，不设会直接崩。
#
# COVERAGE_CORE=ctrace：coverage 7.x 在 Python 3.13 上默认用 sysmon 核心，
# 与多线程 + GC 组合时会偶发 "Windows fatal exception: code 0x80000003"
# （栈在 httpcore._trace，测速上传线程正在跑），pytest 进程被直接杀掉。
# 改用传统 ctrace 核心可稳定通过；这是针对本机环境的 workaround，
# 等 coverage 升级后应复测并考虑去掉。
CHILD_ENV = {**os.environ, "PYTHONUTF8": "1", "COVERAGE_CORE": "ctrace"}

SMOKE_MODULES = [
    "netopt",
    "netopt.models",
    "netopt.domain",
    "netopt.ui",
    "netopt.platform",
    "netopt.parsers",
    "netopt.probes",
    "netopt.state",
    "netopt.diag",
    "netopt.fix",
    "netopt.health",
]

#: 覆盖率门槛与报告格式（T0.7）
COVERAGE_ARGS = [
    "--cov=netopt",
    "--cov-fail-under=90",
    "--cov-report=term-missing",
]

#: 需要外部 CLI 的门禁项：(显示名, argv)。找不到可执行文件时给出安装提示。
TOOL_STEPS = [
    ("ruff check", ["ruff", "check", "."]),
    ("ruff format", ["ruff", "format", "--check", "."]),
    ("mypy", ["mypy", "netopt"]),
    ("tach", ["tach", "check"]),
    ("bandit", ["bandit", "-r", "netopt", "-q"]),
]

INSTALL_HINT = {
    "ruff": "uv sync 或 pip install ruff",
    "mypy": "uv sync 或 pip install mypy",
    "tach": "uv sync 或 pip install tach",
    "bandit": "uv sync 或 pip install bandit",
}


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
    """跑一个外部 CLI；找不到可执行文件时返回失败 + 明确安装提示。"""
    exe = shutil.which(argv[0])
    if exe is None:
        hint = INSTALL_HINT.get(argv[0], "请先安装该命令行工具")
        return False, f"找不到 {argv[0]}（未安装或不在 PATH；{hint}）"
    p = subprocess.run(
        [exe, *argv[1:]],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        errors="replace",
        env=CHILD_ENV,
    )
    return p.returncode == 0, (p.stdout + p.stderr).strip()


def _step_tool(name: str, argv: list[str]) -> bool:
    ok, out = _run_tool(argv)
    return _say(name, ok, "" if ok else "\n" + out)


def step_pytest(extra: list[str], *, coverage: bool) -> bool:
    """跑测试。``coverage=True`` 时附加覆盖率门槛（T0.7）。"""
    argv = [
        sys.executable,
        "-m",
        "pytest",
        *(COVERAGE_ARGS if coverage else []),
        *extra,
    ]
    p = subprocess.run(
        argv,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        errors="replace",
        env=CHILD_ENV,
    )
    out = (p.stdout + p.stderr).strip()
    lines = [line for line in out.splitlines() if line.strip()]
    if p.returncode != 0:
        detail = "\n" + "\n".join(lines[-20:])
    else:
        # 成功时挑出「N passed」与覆盖率两行，方便一眼看数字
        picked = [line for line in lines if " passed" in line or "Total coverage" in line]
        detail = "  ".join(picked[-2:]) if picked else (lines[-1] if lines else "")
    return _say("pytest", p.returncode == 0, detail)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--fast",
        action="store_true",
        help="只跑 import 冒烟 + pytest（不含覆盖率门槛），跳过 lint/类型/分层/安全",
    )
    args, extra = ap.parse_known_args()  # 不认识的参数透传给 pytest

    _enable_utf8_console()
    print(f"net-optimizer 门禁  (root={ROOT})\n" + "-" * 56)
    results = [step_smoke()]
    if not args.fast:
        for name, argv in TOOL_STEPS:
            results.append(_step_tool(name, argv))
    results.append(step_pytest(extra, coverage=not args.fast))
    print("-" * 56)
    passed, total = sum(results), len(results)
    print(f"{passed}/{total} 项通过")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
