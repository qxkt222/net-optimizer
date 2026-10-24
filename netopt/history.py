# -*- coding: utf-8 -*-
"""JSONL 历史记录：追加、读取、取最近一条。

与 v1 ``state.hist_add`` 的区别：

- 按行追加（JSONL），不重写整个文件；
- 读取时**跳过坏行**而不是把整份历史当空；
- 写入失败向上抛 ``OSError``，由命令层决定如何提示，绝不静默吞掉。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast


def append(path: Path, record: dict[str, Any]) -> None:
    """追加一条记录并立即 flush。IO 失败原样抛给调用方。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        handle.flush()


def load(path: Path, *, limit: int | None = None) -> list[dict[str, Any]]:
    """读取全部记录；文件不存在返回空列表，坏行跳过。

    ``limit`` 给定时只返回**最后** N 条。
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            records.append(value)
    if limit is not None and limit >= 0:
        return records[-limit:] if limit else []
    return records


def last(path: Path, *, kind: str) -> dict[str, Any] | None:
    """最近一条 ``kind`` 匹配的记录；没有则返回 ``None``。"""
    for record in reversed(load(path)):
        if record.get("kind") == kind:
            # mypy 2.4 对 dict[str, Any] 的返回值报 no-any-return；显式收窄类型。
            return cast(dict[str, Any], record)
    return None
