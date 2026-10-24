# -*- coding: utf-8 -*-
"""变更日志 —— 修复操作的 intent → 执行 → 结果事件流。

设计要点（``docs/SPEC.md`` §11、``docs/TASKS.md`` T4.1）：

- 文件是 JSONL：一行一个 :class:`~netopt.domain.changes.Change` 快照；
- :meth:`Journal.begin` 必须**先把 intent 落盘并 fsync** 才返回；写失败抛
  :class:`JournalError`，此时调用方绝不能执行修复；
- :meth:`Journal.complete` / :meth:`Journal.fail` / :meth:`Journal.mark_undone`
  追加同 id 的新记录，读取时按 id 折叠出最新状态 —— 进程中途被杀也能据此
  判断哪些修复是半成品；
- :meth:`Journal.load` 容忍坏行（跳过并计数），但文件本身读不了会抛异常，
  不静默吞错；
- 本模块只存取记录，**不执行** ``undo`` 里的命令，也不加文件锁（单进程使用）。
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netopt.domain.changes import Change, ChangeStatus

__all__ = ["Journal", "JournalError"]


class JournalError(RuntimeError):
    """变更日志读写失败。

    ``begin`` 抛此异常时表示 intent 没有落盘，调用方不得继续执行修复。
    """


def _new_id() -> str:
    """生成变更 id：微秒时间戳 + 短随机后缀，同一毫秒内也不会撞。"""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    return f"{stamp}-{secrets.token_hex(4)}"


class Journal:
    """单个 JSONL 变更日志文件的读写门面。

    每次写入都是追加一整行并 ``fsync``；读取时按 ``id`` 折叠，保留每条变更
    最后一次出现的状态。实例不缓存文件内容，每次查询都重新读盘，便于测试
    与外部工具就地追加。
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    # ------------------------------------------------------------------ 写入

    def begin(
        self,
        *,
        kind: str,
        target: str,
        before: dict[str, Any],
        after: dict[str, Any],
        undo: list[list[str]],
    ) -> Change:
        """写入一条 ``intent`` 记录并 fsync，返回该记录。

        写盘失败抛 :class:`JournalError`；**收到异常时调用方不得执行修复**。
        """
        change = Change(
            id=_new_id(),
            ts=datetime.now(UTC),
            kind=kind,
            target=target,
            before=before,
            after=after,
            undo=undo,
            status=ChangeStatus.intent,
        )
        self._append(change)
        return change

    def complete(self, change_id: str, *, result: str | None = None) -> Change:
        """把变更标记为 ``applied`` 并追加一条同 id 的新记录。"""
        return self._transition(change_id, ChangeStatus.applied, result=result)

    def fail(self, change_id: str, *, error: str) -> Change:
        """把变更标记为 ``failed``，``error`` 写入 ``result`` 供排查。"""
        return self._transition(change_id, ChangeStatus.failed, result=error)

    def mark_undone(self, change_id: str) -> Change:
        """把变更标记为 ``undone``（回滚已执行），清空旧的执行结果。"""
        return self._transition(change_id, ChangeStatus.undone, result=None)

    def _transition(self, change_id: str, status: ChangeStatus, *, result: str | None) -> Change:
        """在现有记录上改状态，追加为新事件；``ts`` 保留创建时刻。"""
        current = self.get(change_id)
        if current is None:
            raise JournalError(f"变更记录不存在: {change_id}")
        updated = current.model_copy(update={"status": status, "result": result})
        self._append(updated)
        return updated

    def _append(self, change: Change) -> None:
        """追加一行 JSON 并 fsync；任何写盘失败都转成 :class:`JournalError`。"""
        line = change.model_dump_json()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as exc:
            raise JournalError(f"写入变更日志失败: {self.path}: {exc}") from exc

    # ------------------------------------------------------------------ 读取

    def load_with_errors(self) -> tuple[list[Change], list[str]]:
        """读取全部记录并按 id 折叠为最新状态，同时返回坏行说明。

        文件不存在或为空时返回 ``([], [])``；无法解析的行被跳过，其行号与
        原因放进第二个返回值。文件本身读不了（权限、IO 错误）则抛
        :class:`JournalError`。
        """
        latest: dict[str, Change] = {}
        errors: list[str] = []
        try:
            with self.path.open(encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        change = Change.model_validate(json.loads(text))
                    except (ValueError, TypeError) as exc:
                        errors.append(f"第 {lineno} 行无法解析: {exc}")
                        continue
                    latest[change.id] = change
        except FileNotFoundError:
            return [], []
        except OSError as exc:
            raise JournalError(f"读取变更日志失败: {self.path}: {exc}") from exc
        return list(latest.values()), errors

    def load(self) -> list[Change]:
        """返回按 id 折叠后的最新记录（保持首次出现的顺序），坏行静默跳过。"""
        changes, _ = self.load_with_errors()
        return changes

    def pending(self) -> list[Change]:
        """返回最新状态仍为 ``intent`` 的记录（进程中断留下的半成品）。"""
        return [c for c in self.load() if c.status is ChangeStatus.intent]

    def last_applied(self) -> Change | None:
        """返回最后一条状态为 ``applied`` 的变更；没有则返回 ``None``。"""
        found: Change | None = None
        for change in self.load():
            if change.status is ChangeStatus.applied:
                found = change
        return found

    def get(self, change_id: str) -> Change | None:
        """按 id 取最新记录；不存在返回 ``None``。"""
        for change in self.load():
            if change.id == change_id:
                return change
        return None
