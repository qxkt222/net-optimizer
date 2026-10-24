# -*- coding: utf-8 -*-
"""变更日志测试 —— intent 落盘、事件流折叠、坏行容忍与失败路径。

全部在 ``tmp_path`` 下进行，不执行任何 ``undo`` 命令，也不碰真实状态文件。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netopt.domain.changes import Change, ChangeStatus
from netopt.system.journal import Journal, JournalError


def _begin(journal: Journal) -> Change:
    """写一条典型的 DNS 修复 intent。"""
    return journal.begin(
        kind="dns",
        target="以太网",
        before={"servers": ["192.0.2.1"]},
        after={"servers": ["223.5.5.5", "119.29.29.29"]},
        undo=[["netsh", "interface", "ip", "set", "dnsservers", "以太网", "static", "192.0.2.1"]],
    )


def test_begin_writes_intent_before_returning(tmp_path: Path) -> None:
    """begin 返回时文件里已经有 intent 行，重新读回状态一致。"""
    path = tmp_path / "changes.jsonl"
    journal = Journal(path)
    change = _begin(journal)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    raw = json.loads(lines[0])
    assert raw["id"] == change.id
    assert raw["status"] == "intent"
    assert raw["kind"] == "dns"
    assert raw["target"] == "以太网"
    assert raw["before"] == {"servers": ["192.0.2.1"]}
    assert raw["undo"] == change.undo

    loaded = journal.load()
    assert [c.id for c in loaded] == [change.id]
    assert loaded[0].status is ChangeStatus.intent


def test_complete_marks_applied_and_clears_pending(tmp_path: Path) -> None:
    """complete 后 last_applied 命中该记录，pending 为空。"""
    journal = Journal(tmp_path / "changes.jsonl")
    change = _begin(journal)

    done = journal.complete(change.id, result="已应用到 2 个网卡")
    assert done.id == change.id
    assert done.status is ChangeStatus.applied
    assert done.result == "已应用到 2 个网卡"

    assert journal.pending() == []
    last = journal.last_applied()
    assert last is not None
    assert last.id == change.id
    assert last.status is ChangeStatus.applied


def test_fail_records_error(tmp_path: Path) -> None:
    """fail 把状态与错误一起落盘。"""
    journal = Journal(tmp_path / "changes.jsonl")
    change = _begin(journal)

    failed = journal.fail(change.id, error="需要管理员权限")
    assert failed.status is ChangeStatus.failed
    assert failed.result == "需要管理员权限"
    assert journal.pending() == []

    current = journal.get(change.id)
    assert current is not None
    assert current.status is ChangeStatus.failed
    assert current.result == "需要管理员权限"


def test_event_stream_folds_to_latest(tmp_path: Path) -> None:
    """同 id 多条记录只折叠出一条，状态取最后一次。"""
    path = tmp_path / "changes.jsonl"
    journal = Journal(path)
    change = _begin(journal)
    journal.complete(change.id)
    journal.mark_undone(change.id)

    assert len(path.read_text(encoding="utf-8").splitlines()) == 3
    folded = journal.load()
    assert len(folded) == 1
    assert folded[0].id == change.id
    assert folded[0].status is ChangeStatus.undone
    # undone 既不是待处理，也不能再被 undo last 选中。
    assert journal.pending() == []
    assert journal.last_applied() is None


def test_bad_line_is_skipped_and_counted(tmp_path: Path) -> None:
    """坏行跳过不抛异常，load_with_errors 计数为 1。"""
    path = tmp_path / "changes.jsonl"
    journal = Journal(path)
    change = _begin(journal)
    with path.open("a", encoding="utf-8") as f:
        f.write("not json\n")

    changes, errors = journal.load_with_errors()
    assert [c.id for c in changes] == [change.id]
    assert len(errors) == 1
    # load() 仍然可用，只是静默跳过坏行。
    assert [c.id for c in journal.load()] == [change.id]


def test_pending_after_interrupted_begin(tmp_path: Path) -> None:
    """模拟 begin 之后进程被杀：只有 intent，没有 complete。"""
    journal = Journal(tmp_path / "changes.jsonl")
    change = _begin(journal)

    pending = journal.pending()
    assert [c.id for c in pending] == [change.id]
    assert journal.last_applied() is None


def test_begin_on_unwritable_path_raises_journal_error(tmp_path: Path) -> None:
    """父路径是普通文件时无法落盘，必须抛 JournalError。"""
    blocker = tmp_path / "blocker"
    blocker.write_text("我不是目录", encoding="utf-8")
    journal = Journal(blocker / "changes.jsonl")

    with pytest.raises(JournalError):
        _begin(journal)


def test_load_empty_and_missing_file(tmp_path: Path) -> None:
    """空文件与不存在的文件都返回 []。"""
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert Journal(empty).load() == []
    assert Journal(tmp_path / "missing.jsonl").load() == []


def test_unknown_id_transitions_raise(tmp_path: Path) -> None:
    """对不存在的 id 做状态迁移是编程错误，抛 JournalError。"""
    journal = Journal(tmp_path / "changes.jsonl")
    assert journal.get("nope") is None
    with pytest.raises(JournalError):
        journal.complete("nope")
    with pytest.raises(JournalError):
        journal.fail("nope", error="x")
    with pytest.raises(JournalError):
        journal.mark_undone("nope")
