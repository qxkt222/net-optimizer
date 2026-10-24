# -*- coding: utf-8 -*-
"""``netopt watch`` / ``netopt monitor`` CLI 测试：透传、文本 / JSON 与用法错误。

``netopt.commands.watch.run_watch`` 一律 monkeypatch 成固定样本列表，因此
本文件**不采样、不 sleep、不联网、不写 JSONL**。预期输出按任务书语义手写，
不拿被测渲染的输出反推预期。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import netopt.cli as cli
from netopt.analysis.alerts import Alert
from netopt.commands import watch as watch_cmd
from netopt.domain import Finding, Report, Score, Severity

runner = CliRunner()


def _report(total: int | None = None, *, critical: bool = False) -> Report:
    """构造一份最小 status 报告；``critical`` 控制退出码。"""
    findings: list[Finding] = []
    if critical:
        findings.append(
            Finding(
                code="TEST_CRITICAL",
                severity=Severity.critical,
                title="测试故障",
                detail="用于验证 critical 退出码",
            )
        )
    return Report(
        command="status",
        started_at=datetime.now(UTC),
        duration_ms=1,
        environment={"admin": False},
        sections=[],
        findings=findings,
        errors=[],
        score=None if total is None else Score(total=total, grade="B", items=[]),
    )


def _sample(
    ts: str,
    total: int | None = None,
    *,
    alerts: int = 0,
    critical: bool = False,
) -> watch_cmd.WatchSample:
    """构造一轮样本：``alerts`` 为实际发出的告警条数。"""
    alert_list = [
        Alert(
            code=f"TEST_ALERT_{index}",
            severity=Severity.warn,
            title="测试告警",
            detail="用于验证 JSON 序列化",
            count=1,
        )
        for index in range(alerts)
    ]
    return watch_cmd.WatchSample(
        ts=ts,
        report=_report(total, critical=critical),
        alerts=alert_list,
    )


def _patch_run(
    monkeypatch: pytest.MonkeyPatch,
    samples: list[watch_cmd.WatchSample],
) -> list[dict[str, Any]]:
    """把 ``run_watch`` 换成固定返回值，并记录调用参数。"""
    calls: list[dict[str, Any]] = []

    def fake_run_watch(**kwargs: Any) -> list[watch_cmd.WatchSample]:
        calls.append(kwargs)
        return samples

    monkeypatch.setattr(watch_cmd, "run_watch", fake_run_watch)
    return calls


# ===========================================================================
# watch：JSON
# ===========================================================================
def test_watch_json_outputs_sample_list(monkeypatch: pytest.MonkeyPatch) -> None:
    samples = [
        _sample("2026-10-24T00:00:00+00:00", 80, alerts=1),
        _sample("2026-10-24T00:00:05+00:00", 90),
    ]
    calls = _patch_run(monkeypatch, samples)

    result = runner.invoke(cli.app, ["watch", "--count", "2", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)  # 整段 stdout 可解析 → 没有夹带提示行
    assert isinstance(payload, list)
    assert [item["ts"] for item in payload] == [
        "2026-10-24T00:00:00+00:00",
        "2026-10-24T00:00:05+00:00",
    ]
    assert payload[0]["report"]["command"] == "status"
    assert payload[0]["report"]["score"]["total"] == 80
    assert payload[1]["report"]["score"]["total"] == 90
    assert payload[1]["alerts"] == []
    assert payload[0]["alerts"][0]["severity"] == "warn"
    assert payload[0]["alerts"][0]["code"] == "TEST_ALERT_0"
    assert result.stdout.startswith("[")
    assert len(calls) == 1
    assert calls[0]["interval"] == 5.0
    assert calls[0]["count"] == 2
    assert calls[0]["out_path"] is None
    assert callable(calls[0]["on_sample"]), "JSON 模式同样注入逐轮回调"
    assert "collect" not in calls[0], "JSON 模式保留默认 collect=True（需要完整列表）"


def test_watch_json_uses_critical_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, [_sample("2026-10-24T00:00:00+00:00", 10, critical=True)])

    result = runner.invoke(cli.app, ["watch", "--count", "1", "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload[0]["report"]["findings"][0]["severity"] == "critical"


# ===========================================================================
# watch：文本
# ===========================================================================
def test_watch_text_prints_one_line_per_sample_and_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_run(
        monkeypatch,
        [
            _sample("2026-10-24T00:00:00+00:00", 80, alerts=1),
            _sample("2026-10-24T00:00:05+00:00", 90),
        ],
    )

    result = runner.invoke(cli.app, ["watch", "--count", "2"])

    assert result.exit_code == 0
    out = result.stdout
    assert "2026-10-24T00:00:00+00:00" in out
    assert "2026-10-24T00:00:05+00:00" in out
    assert "分数 80" in out
    assert "分数 90" in out
    assert "告警 1" in out
    assert "告警 0" in out
    assert "采样结束" in out
    assert "共 2 轮" in out
    assert "平均分 85.0" in out
    assert "告警 1 条" in out


def test_watch_text_without_score_shows_dash(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, [_sample("2026-10-24T00:00:00+00:00", None)])

    result = runner.invoke(cli.app, ["watch", "--count", "1"])

    assert result.exit_code == 0
    assert "分数 -" in result.stdout
    assert "平均分 -" in result.stdout


def test_watch_text_mode_passes_streaming_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    """文本模式必须注入逐轮回调并关闭累积（collect=False）。"""
    samples = [
        _sample("2026-10-24T00:00:00+00:00", 80, alerts=1),
        _sample("2026-10-24T00:00:05+00:00", 90),
    ]
    calls: list[dict[str, Any]] = []

    def streaming_run(**kwargs: Any) -> list[watch_cmd.WatchSample]:
        calls.append(kwargs)
        assert kwargs["collect"] is False
        for sample in samples:
            kwargs["on_sample"](sample)
        return []

    monkeypatch.setattr(watch_cmd, "run_watch", streaming_run)

    result = runner.invoke(cli.app, ["watch", "--count", "2"])

    assert result.exit_code == 0
    assert len(calls) == 1
    assert calls[0]["interval"] == 5.0
    assert calls[0]["count"] == 2
    out = result.stdout
    assert out.index("2026-10-24T00:00:00+00:00") < out.index("2026-10-24T00:00:05+00:00")
    assert "分数 80" in out
    assert "分数 90" in out
    assert "告警 1" in out
    assert "采样结束：共 2 轮，平均分 85.0，告警 1 条" in out


def test_watch_streamed_critical_sample_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    """collect=False 时退出码仍要看回调收到的样本（不能因为返回空列表就变 0）。"""
    samples = [_sample("2026-10-24T00:00:00+00:00", 10, critical=True)]

    def streaming_run(**kwargs: Any) -> list[watch_cmd.WatchSample]:
        for sample in samples:
            kwargs["on_sample"](sample)
        return []

    monkeypatch.setattr(watch_cmd, "run_watch", streaming_run)

    result = runner.invoke(cli.app, ["watch", "--count", "1"])

    assert result.exit_code == 2


# ===========================================================================
# watch：参数透传
# ===========================================================================
def test_watch_passes_interval_count_and_out(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = _patch_run(monkeypatch, [_sample("T1", 70)])
    out_path = tmp_path / "metrics.jsonl"

    result = runner.invoke(
        cli.app,
        ["watch", "--interval", "0.5", "--count", "1", "--out", str(out_path)],
    )

    assert result.exit_code == 0
    assert len(calls) == 1
    assert calls[0]["interval"] == 0.5
    assert calls[0]["count"] == 1
    assert Path(calls[0]["out_path"]) == out_path


# ===========================================================================
# watch：用法错误
# ===========================================================================
def test_watch_json_without_count_is_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_run(monkeypatch, [])

    result = runner.invoke(cli.app, ["watch", "--json"])

    assert result.exit_code == 1
    assert "--count" in result.stderr
    assert calls == [], "用法错误必须在采样前返回"


def test_watch_global_json_without_count_is_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_run(monkeypatch, [])

    result = runner.invoke(cli.app, ["--json", "watch"])

    assert result.exit_code == 1
    assert "--count" in result.stderr
    assert calls == []


def test_watch_keyboard_interrupt_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """无 --count 时常驻采样靠 Ctrl+C 结束；CLI 必须给出提示而不是裸栈。"""

    def interrupt(**kwargs: Any) -> list[watch_cmd.WatchSample]:
        raise KeyboardInterrupt

    monkeypatch.setattr(watch_cmd, "run_watch", interrupt)

    result = runner.invoke(cli.app, ["watch"])

    assert result.exit_code == 1
    assert "已中断" in result.stderr


@pytest.mark.parametrize(
    "argv",
    [
        ["watch", "--count=-1"],
        ["watch", "--interval=-1"],
    ],
)
def test_watch_negative_values_are_usage_errors(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
) -> None:
    calls = _patch_run(monkeypatch, [])

    result = runner.invoke(cli.app, argv)

    assert result.exit_code == 1
    assert "用法错误" in result.stderr
    assert calls == []


# ===========================================================================
# monitor：等价于 watch --interval 1 --count 60（文本）
# ===========================================================================
def test_monitor_defaults_to_watch_interval_one_count_sixty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_run(monkeypatch, [_sample("T1", 80)])

    result = runner.invoke(cli.app, ["monitor"])

    assert result.exit_code == 0
    assert len(calls) == 1
    assert calls[0]["interval"] == 1.0
    assert calls[0]["count"] == 60
    assert calls[0]["out_path"] is None
    assert calls[0]["collect"] is False, "文本模式不累积样本（常驻不爆内存）"
    assert callable(calls[0]["on_sample"]), "文本模式必须注入逐轮回调"
    assert "分数 80" in result.stdout
    assert "采样结束" in result.stdout


def test_monitor_accepts_count_and_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_run(monkeypatch, [])

    result = runner.invoke(cli.app, ["monitor", "-n", "3", "--interval", "2"])

    assert result.exit_code == 0
    assert len(calls) == 1
    assert calls[0]["interval"] == 2.0
    assert calls[0]["count"] == 3
    assert calls[0]["out_path"] is None
    assert calls[0]["collect"] is False
    assert callable(calls[0]["on_sample"])
    assert "共 0 轮" in result.stdout
