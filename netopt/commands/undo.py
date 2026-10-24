# -*- coding: utf-8 -*-
"""回滚命令 —— 按 journal 里记录的 ``undo`` argv 还原系统状态。

与 :mod:`netopt.commands.fix` 的分工（``docs/SPEC.md`` §11、``docs/TASKS.md``
T4.5）：

- 修复层只把「怎么回滚」写成 argv 记进 transaction journal，**不执行**；
  本模块负责挑出最近一条 ``applied`` 记录并逐条执行它的 ``undo``。
- 只有**所有**命令都成功才 ``journal.mark_undone``；任何一条失败就立即停止，
  把失败项与原因返回给调用方，记录保持 ``applied``（仍可再次尝试）。
- 本模块**不打印**：结果全部通过 :class:`UndoResult` 返回，由 CLI / GUI 决定
  怎么展示。

依赖解析：``journal`` 默认在调用时构造 ``Journal(paths.journal_path())``，
``run`` 默认取 :func:`netopt.platform.run`；两者都允许测试注入。
"""

from __future__ import annotations

from dataclasses import dataclass

from netopt import paths, platform
from netopt.domain.changes import Change, ChangeStatus
from netopt.platform import CmdResult, Runner
from netopt.system.journal import Journal

__all__ = ["UndoResult", "undo", "undo_last"]

#: 找不到可回滚记录时的固定说明。
_NO_CHANGE = "没有可回滚的变更"
#: 记录存在但 ``undo`` 为空时的固定说明。
_NO_STEPS = "该变更没有可自动回滚的步骤"


@dataclass(frozen=True)
class UndoResult:
    """一次回滚的结果。

    ``change_id`` 是实际选中的变更；没有选中任何记录时为 ``None``。
    ``executed`` 是**成功执行**的命令条数；``failed`` 是
    ``(argv, 错误说明)``，非空表示回滚中途停止且记录未被标记为 ``undone``。
    """

    change_id: str | None
    executed: int
    failed: list[tuple[list[str], str]]
    message: str


# ---------------------------------------------------------------------------
# 依赖解析
# ---------------------------------------------------------------------------
def _resolve_journal(journal: Journal | None) -> Journal:
    """在**调用时**解析 ``journal``：默认使用运行期状态目录里的变更日志。"""
    return journal if journal is not None else Journal(paths.journal_path())


def _resolve_run(run: Runner | None) -> Runner:
    """在**调用时**解析 ``run``：默认取 :func:`netopt.platform.run`。"""
    return run if run is not None else platform.run


def is_admin() -> bool:
    """当前进程是否以管理员身份运行（供 CLI 权限门使用）。

    放在命令层是为了让 ``netopt.cli`` 保持只依赖 ``netopt.commands``，
    不必直接 import ``netopt.platform``（tach 分层约束）。
    """
    return platform.is_admin()


# ---------------------------------------------------------------------------
# 选择记录
# ---------------------------------------------------------------------------
def _last_applied(journal: Journal, kind: str | None) -> Change | None:
    """返回最后一条 ``applied`` 记录；``kind`` 给定时只看该类型。

    与 :meth:`Journal.last_applied` 口径一致：按 ``load()`` 折叠后的顺序取
    最后一条，``undone`` / ``failed`` / ``intent`` 都不会被选中。
    """
    found: Change | None = None
    for change in journal.load():
        if change.status is not ChangeStatus.applied:
            continue
        if kind is not None and change.kind != kind:
            continue
        found = change
    return found


# ---------------------------------------------------------------------------
# 执行
# ---------------------------------------------------------------------------
def _one_line(text: str, limit: int = 80) -> str:
    """把命令输出压成一行，最多 ``limit`` 个字符。"""
    return " ".join(text.split())[:limit]


def _result_error(argv: list[str], result: CmdResult) -> str:
    """把一条失败命令翻译成可读原因（与修复层的口径一致）。"""
    if result.timed_out:
        reason = "命令执行超时"
    elif result.missing:
        reason = "系统不支持该命令"
    else:
        reason = f"退出码 {result.code}"
        text = _one_line(result.out)
        if text:
            reason = f"{reason}: {text}"
    return f"{' '.join(argv)} → {reason}"


def _execute_undo(
    change: Change,
    *,
    journal: Journal,
    run: Runner,
) -> UndoResult:
    """逐条执行 ``change.undo``；全部成功后才标记 ``undone``。"""
    if not change.undo:
        return UndoResult(
            change_id=change.id,
            executed=0,
            failed=[],
            message=_NO_STEPS,
        )

    executed = 0
    for raw_argv in change.undo:
        argv = [str(item) for item in raw_argv]
        result = run(argv)
        if not result.ok:
            return UndoResult(
                change_id=change.id,
                executed=executed,
                failed=[(argv, _result_error(argv, result))],
                message="回滚失败，已停止后续步骤；该变更仍未标记为已回滚",
            )
        executed += 1

    journal.mark_undone(change.id)
    return UndoResult(
        change_id=change.id,
        executed=executed,
        failed=[],
        message=f"已回滚 {executed} 条命令",
    )


# ---------------------------------------------------------------------------
# 公开入口
# ---------------------------------------------------------------------------
def undo_last(
    *,
    kind: str | None = None,
    journal: Journal | None = None,
    run: Runner | None = None,
) -> UndoResult:
    """回滚最后一条已应用的变更。

    ``kind`` 给定时只在同类型记录里挑（例如 ``kind="dns"`` 对应 v1 的
    ``fix dns --restore``）。找不到记录时返回 ``change_id=None`` 与
    ``message="没有可回滚的变更"``，不执行任何命令。
    """
    book = _resolve_journal(journal)
    change = _last_applied(book, kind)
    if change is None:
        return UndoResult(change_id=None, executed=0, failed=[], message=_NO_CHANGE)
    return _execute_undo(change, journal=book, run=_resolve_run(run))


def undo(
    change_id: str,
    *,
    journal: Journal | None = None,
    run: Runner | None = None,
) -> UndoResult:
    """按 id 回滚指定变更。

    记录不存在或当前不处于 ``applied`` 状态（已被回滚 / 失败 / 尚未完成）
    时视为「没有可回滚的变更」，不执行任何命令。
    """
    book = _resolve_journal(journal)
    change = book.get(change_id)
    if change is None or change.status is not ChangeStatus.applied:
        return UndoResult(change_id=None, executed=0, failed=[], message=_NO_CHANGE)
    return _execute_undo(change, journal=book, run=_resolve_run(run))
