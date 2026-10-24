# -*- coding: utf-8 -*-
"""运行期目录解析 —— v2 的配置 / 状态 / 日志 / 原始证据放在哪里。

优先级（见 ``docs/SPEC.md`` §12）：

1. 环境变量 ``NETOPT_HOME``：测试与高级用户显式指定根目录；
2. ``%LOCALAPPDATA%\\net-optimizer``：默认位置，装到 Program Files 也能写；
3. 便携模式（``portable=True``）：程序根目录，保留 v1 行为，优先于环境变量。

除 :func:`ensure_dirs` 外，本模块所有函数都只做**纯路径拼接**，不创建目录、
不写文件；调用方在真正落盘前必须先显式调用 :func:`ensure_dirs`。
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = [
    "app_dir",
    "config_path",
    "ensure_dirs",
    "history_path",
    "journal_path",
    "logs_dir",
    "raw_dir",
    "state_dir",
]

#: 默认根目录名，同时也是 ``%LOCALAPPDATA%`` 下的子目录名。
_APP_NAME = "net-optimizer"


def app_dir(*, portable: bool = False) -> Path:
    """返回运行期根目录的路径（不创建、不检查是否存在）。

    ``portable=True`` 时直接使用程序根目录（``netopt`` 的上一级），
    此时**忽略** ``NETOPT_HOME`` 与 ``%LOCALAPPDATA%``。
    否则依次尝试 ``NETOPT_HOME``、``%LOCALAPPDATA%\\net-optimizer``。
    """
    if portable:
        return Path(__file__).resolve().parent.parent

    home = os.environ.get("NETOPT_HOME")
    if home:
        return Path(home).expanduser()

    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata).expanduser() / _APP_NAME

    # 环境变量缺失时的兜底；本项目只承诺 Windows，这里沿用同一目录形状。
    return Path.home() / "AppData" / "Local" / _APP_NAME


def _base(base: Path | None, *, portable: bool) -> Path:
    """把可选的 ``base`` 参数解析成实际根目录。"""
    return Path(base) if base is not None else app_dir(portable=portable)


def state_dir(base: Path | None = None, *, portable: bool = False) -> Path:
    """状态目录 ``<root>/state``，存放 history / changes 两个 JSONL。"""
    return _base(base, portable=portable) / "state"


def journal_path(base: Path | None = None, *, portable: bool = False) -> Path:
    """变更日志路径 ``<root>/state/changes.jsonl``。"""
    return state_dir(base, portable=portable) / "changes.jsonl"


def history_path(base: Path | None = None, *, portable: bool = False) -> Path:
    """诊断历史路径 ``<root>/state/history.jsonl``。"""
    return state_dir(base, portable=portable) / "history.jsonl"


def logs_dir(base: Path | None = None, *, portable: bool = False) -> Path:
    """日志目录 ``<root>/logs``。"""
    return _base(base, portable=portable) / "logs"


def raw_dir(
    base: Path | None = None,
    *,
    portable: bool = False,
    run_id: str | None = None,
) -> Path:
    """原始证据目录 ``<root>/raw``；给出 ``run_id`` 时返回 ``<root>/raw/<run_id>``。

    ``run_id`` 必须是单级目录名：空串、``.``、``..`` 或含路径分隔符一律抛
    :class:`ValueError`，避免写到 ``raw`` 之外。
    """
    root = _base(base, portable=portable) / "raw"
    if run_id is None:
        return root
    if not run_id or run_id in {".", ".."} or "/" in run_id or "\\" in run_id:
        raise ValueError(f"非法 run_id（必须是单级目录名）: {run_id!r}")
    return root / run_id


def config_path(base: Path | None = None, *, portable: bool = False) -> Path:
    """配置文件路径 ``<root>/config.toml``。"""
    return _base(base, portable=portable) / "config.toml"


def ensure_dirs(base: Path | None = None, *, portable: bool = False) -> Path:
    """创建运行期目录并返回根目录；已存在不算错（幂等）。

    只创建 ``state`` / ``logs`` / ``raw`` 三个目录，**不创建** ``config.toml``
    —— 那份文件由配置层按需写出。
    """
    root = _base(base, portable=portable)
    for child in ("state", "logs", "raw"):
        (root / child).mkdir(parents=True, exist_ok=True)
    return root
