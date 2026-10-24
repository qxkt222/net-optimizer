# -*- coding: utf-8 -*-
"""变更记录 —— 修复操作的 intent / result 事件模型。

每次修复（DNS / TCP / 电源 / 注册表）都由 :mod:`netopt.system.journal` 写成
一条 :class:`Change`：先落盘 ``intent``，执行后再追加 ``applied`` /
``failed`` / ``undone``。同一 ``id`` 的多条记录构成事件流，读取时按 id 折叠
成最新状态。

本模块只定义数据结构，不读写文件、不执行 ``undo`` 里的命令。
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict

__all__ = ["Change", "ChangeStatus"]

# 与 Report 契约保持一致：冻结 + 忽略未知字段（旧版本读到新字段不会炸）。
_FROZEN = ConfigDict(frozen=True, extra="ignore")


class ChangeStatus(StrEnum):
    """一条变更的生命周期状态。

    - ``intent``：已决定修改并落盘，但尚未执行（进程在此状态被杀即为半成品）；
    - ``applied``：执行成功；
    - ``failed``：执行失败，需要回滚或人工介入；
    - ``undone``：已按 ``undo`` 回滚。
    """

    intent = "intent"
    applied = "applied"
    failed = "failed"
    undone = "undone"


class Change(BaseModel):
    """一次修复的完整快照。

    ``before`` / ``after`` 是结构化的原值与目标值，供渲染与排查使用；
    ``undo`` 是**可直接执行的 argv 列表**，由修复层填好，日志层只存不跑。
    ``id`` 由 journal 生成（时间戳 + 短随机），同一 id 的历史记录按时间
    先后追加。
    """

    model_config = _FROZEN

    schema_version: int = 1
    id: str
    ts: datetime
    #: 修复类型：``dns`` / ``tcp`` / ``power`` / ``registry``。
    kind: str
    target: str
    before: dict[str, Any]
    after: dict[str, Any]
    undo: list[list[str]] = []
    status: ChangeStatus = ChangeStatus.intent
    #: 执行结果或错误说明；``None`` 表示尚未有结果。
    result: str | None = None
