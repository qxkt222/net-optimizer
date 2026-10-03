"""日志 / 历史 / dev 标志 / DNS 备份路径。

路径保持现状：程序根目录（缺陷 D12「状态文件不可重定位」本轮不搬家）。

**关键约束**：所有函数在*调用时*从模块全局读取 ``BASE`` / ``HISTORY_FILE`` 等，
不能捕获成默认参数或提前算好——``tests/conftest.py`` 的隔离夹具直接 patch 这些
模块属性，提前算路径就追不到（这是踩过的坑）。
"""

from __future__ import annotations

import json
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
HISTORY_FILE = BASE / "history.json"
DEV_FILE = BASE / "dev.json"
DNS_BACKUP_FILE = BASE / "dns-backup.json"

DEV_ON = False  # 开发者模式：回显所有系统命令的原始输出


def log(msg: str) -> None:
    """追加一行到当天的日志文件（``log-YYYY-MM-DD.log``）。失败静默忽略。"""
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        filename = BASE / f"log-{time.strftime('%Y-%m-%d')}.log"
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def hist_load() -> dict:
    """读取诊断历史；文件缺失/损坏时返回 ``{"entries": []}``。"""
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"entries": []}


def hist_add(entry: dict) -> None:
    """追加一条历史（``{"cmd": ..., "ts": ..., "score": ..., "detail": {...}}``）。

    只保留最近 200 条；写盘失败静默忽略（历史不是关键路径）。
    """
    try:
        h = hist_load()
        h.setdefault("entries", []).append(entry)
        h["entries"] = h["entries"][-200:]
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(h, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def load_dev() -> None:
    """从 ``dev.json`` 读取 dev 开关到模块全局 ``DEV_ON``。"""
    global DEV_ON
    try:
        with open(DEV_FILE, encoding="utf-8") as f:
            DEV_ON = bool(json.load(f).get("dev"))
    except Exception:
        DEV_ON = False


def clear() -> list[str]:
    """删除 ``log-*.log`` / ``history.json`` / ``dev.json``，返回被删文件名。

    供 CLI ``clear`` 与 GUI「清除日志」按钮共用（缺陷 D14：旧实现两处各一份）。
    注意**不删** ``DNS_BACKUP_FILE``——那是 ``fix dns`` 还原用的备份。
    """
    targets: list[Path] = [*sorted(BASE.glob("log-*.log")), HISTORY_FILE, DEV_FILE]
    removed: list[str] = []
    for path in targets:
        try:
            if path.exists():
                path.unlink()
                removed.append(path.name)
        except OSError:
            pass
    return removed
