"""state 模块测试：日志 / 历史 / dev / clear。

全部依赖 ``conftest.py`` 的 ``_isolate_state`` 夹具把路径重定向到 tmp_path。
**如果实现把路径提前算死（不在调用时读模块全局），这些测试会写到真实程序目录，
断言就会失败** —— 这正是本文件的守卫目标。
"""

from __future__ import annotations

import json
import time

from netopt import state


def test_log_writes_into_isolated_base() -> None:
    """日志落到被 patch 的 BASE（证明路径是调用时读取的）。"""
    state.log("测试消息")

    logs = sorted(state.BASE.glob("log-*.log"))
    assert len(logs) == 1, f"应恰好生成一个日志文件，实际 {logs}"
    text = logs[0].read_text(encoding="utf-8")
    assert "测试消息" in text
    assert time.strftime("%Y-%m-%d") in logs[0].name


def test_log_never_raises_when_base_missing(monkeypatch, tmp_path) -> None:
    """日志路径不可写时静默忽略，不能把异常抛给调用方。"""
    monkeypatch.setattr(state, "BASE", tmp_path / "no" / "such" / "dir")
    state.log("写不进去也不该炸")


def test_hist_load_missing_file_returns_empty() -> None:
    assert state.hist_load() == {"entries": []}


def test_hist_load_corrupt_file_returns_empty() -> None:
    state.HISTORY_FILE.write_text("{不是合法 json", encoding="utf-8")
    assert state.hist_load() == {"entries": []}


def test_hist_add_then_load_roundtrip() -> None:
    entry = {"cmd": "status", "ts": "2026-10-03 12:00:00", "score": 88, "detail": {"x": 1}}
    state.hist_add(entry)

    assert state.HISTORY_FILE.exists()
    data = json.loads(state.HISTORY_FILE.read_text(encoding="utf-8"))
    assert data == {"entries": [entry]}
    assert state.hist_load()["entries"] == [entry]


def test_hist_add_caps_at_200_entries() -> None:
    for i in range(205):
        state.hist_add({"cmd": f"c{i}"})

    entries = state.hist_load()["entries"]
    assert len(entries) == 200
    # 保留最近的 200 条：最早的 5 条被丢弃
    assert entries[0]["cmd"] == "c5"
    assert entries[-1]["cmd"] == "c204"


def test_load_dev_reads_flag_and_missing_resets(monkeypatch) -> None:
    monkeypatch.setattr(state, "DEV_ON", False)
    state.DEV_FILE.write_text('{"dev": true}', encoding="utf-8")
    state.load_dev()
    assert state.DEV_ON is True

    state.DEV_FILE.unlink()
    state.load_dev()
    assert state.DEV_ON is False


def test_clear_removes_logs_history_dev_but_keeps_dns_backup() -> None:
    today = time.strftime("%Y-%m-%d")
    log_a = state.BASE / f"log-{today}.log"
    log_b = state.BASE / "log-2020-01-01.log"
    log_a.write_text("a", encoding="utf-8")
    log_b.write_text("b", encoding="utf-8")
    state.hist_add({"cmd": "x"})
    state.DEV_FILE.write_text('{"dev": true}', encoding="utf-8")
    # DNS 备份必须保留：fix dns 还原要用
    state.DNS_BACKUP_FILE.write_text("{}", encoding="utf-8")

    removed = state.clear()

    assert set(removed) == {log_a.name, log_b.name, "history.json", "dev.json"}
    assert not log_a.exists() and not log_b.exists()
    assert not state.HISTORY_FILE.exists()
    assert not state.DEV_FILE.exists()
    assert state.DNS_BACKUP_FILE.exists(), "clear() 不应删除 DNS 备份"


def test_clear_on_empty_base_returns_empty_list() -> None:
    assert state.clear() == []


def test_state_path_constants_are_consistent() -> None:
    """D12 本轮不搬家：文件名保持旧契约，全部位于 BASE 下。"""
    names = {
        state.HISTORY_FILE.name,
        state.DEV_FILE.name,
        state.DNS_BACKUP_FILE.name,
    }
    assert names == {"history.json", "dev.json", "dns-backup.json"}
    for path in (state.HISTORY_FILE, state.DEV_FILE, state.DNS_BACKUP_FILE):
        assert path.parent == state.BASE
