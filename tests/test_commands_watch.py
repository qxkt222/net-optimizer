# -*- coding: utf-8 -*-
"""``netopt.commands.watch`` 测试：采样、JSONL 落盘、停止、冷却与写盘失败。

所有用例都注入 fake builder / 可控时钟 / fake sleep / 临时 ``out_path``：
本文件**不联网、不执行系统命令、不真实等待**。预期值按任务书语义手算，
不拿被测函数的输出反推预期。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

from netopt import history
from netopt.analysis.alerts import AlertEngine
from netopt.commands import status as status_cmd
from netopt.commands import watch as watch_cmd
from netopt.domain import (
    Finding,
    Metric,
    ProbeError,
    ProbeErrorCode,
    Report,
    Score,
    Section,
    Severity,
)


# ---------------------------------------------------------------------------
# 测试替身
# ---------------------------------------------------------------------------
@dataclass
class _Clock:
    """可控单调时钟：测试按需推进，绝不依赖真实时间。"""

    value: float = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class _Event:
    """最小停止事件替身，只实现 ``is_set()`` / ``set()``。"""

    def __init__(self) -> None:
        self._set = False

    def set(self) -> None:
        self._set = True

    def is_set(self) -> bool:
        return self._set


@dataclass
class _Sleeper:
    """记录每次 sleep；可选推进时钟，用于验证冷却跨轮生效。"""

    clock: _Clock | None = None
    calls: list[float] = field(default_factory=list)

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        if self.clock is not None:
            self.clock.advance(seconds)


def _finding(
    code: str = "WAN_LATENCY_HIGH",
    severity: Severity = Severity.critical,
) -> Finding:
    """构造一条最小可用的 Finding。"""
    return Finding(code=code, severity=severity, title=code, detail=f"{code} 的说明")


def _metric(key: str = "latency", value: float | None = 12.5) -> Metric:
    """构造一个带单位的指标；``value=None`` 时标成不可用。"""
    return Metric(
        key=key,
        label="延迟",
        value=value,
        unit="ms",
        available=value is not None,
    )


def _report(
    *,
    findings: list[Finding] | None = None,
    sections: list[Section] | None = None,
    score: Score | None = None,
    errors: list[ProbeError] | None = None,
) -> Report:
    """构造一份最小 Report（字段形状与 ``commands.status`` 一致）。"""
    return Report(
        command="status",
        started_at=datetime.now(UTC),
        duration_ms=1,
        environment={"api": "fake"},
        sections=list(sections or []),
        findings=list(findings or []),
        errors=list(errors or []),
        score=score,
    )


# ---------------------------------------------------------------------------
# sample_once
# ---------------------------------------------------------------------------
def test_sample_once_feeds_top_level_and_section_findings() -> None:
    """顶层结论与各节结论都要喂给引擎，并原样返回 Report。"""
    clock = _Clock()
    report = _report(
        findings=[_finding("WAN_UNREACHABLE")],
        sections=[
            Section(
                id="gateway",
                title="网关",
                findings=[_finding("GATEWAY_LATENCY_HIGH", Severity.warn)],
            ),
            Section(id="dns", title="DNS", findings=[_finding("DNS_FAIL")]),
        ],
    )
    builder_calls: list[int] = []

    def builder() -> Report:
        builder_calls.append(1)
        return report

    sample = watch_cmd.sample_once(builder=builder, engine=AlertEngine(now=clock))

    assert builder_calls == [1]
    assert sample.report is report
    assert [alert.code for alert in sample.alerts] == [
        "WAN_UNREACHABLE",
        "GATEWAY_LATENCY_HIGH",
        "DNS_FAIL",
    ]
    # ts 必须是带时区的 ISO8601，可直接进 JSONL
    assert datetime.fromisoformat(sample.ts).tzinfo is not None


def test_sample_once_resolves_default_builder_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """默认 builder 在调用时解析 ``build_status_report``，便于测试替换。"""
    expected = _report()

    def fake_status() -> Report:
        return expected

    monkeypatch.setattr(status_cmd, "build_status_report", fake_status)

    sample = watch_cmd.sample_once(engine=AlertEngine([], now=_Clock()))

    assert sample.report is expected
    assert sample.alerts == []


def test_sample_once_creates_engine_when_not_given() -> None:
    """未注入引擎时也要按默认规则告警（单次调用没有跨轮冷却）。"""
    sample = watch_cmd.sample_once(
        builder=lambda: _report(findings=[_finding("WAN_UNREACHABLE")]),
        now=_Clock(),
    )

    assert [alert.code for alert in sample.alerts] == ["WAN_UNREACHABLE"]


# ---------------------------------------------------------------------------
# run_watch：轮次、落盘与 sleep
# ---------------------------------------------------------------------------
def test_run_watch_count_three_writes_three_jsonl_lines(tmp_path: Path) -> None:
    """count=3 → 3 个样本、3 行 JSONL、sleep 恰好 2 次（最后一轮不睡）。"""
    clock = _Clock()
    sleeper = _Sleeper(clock=clock)
    out_path = tmp_path / "metrics.jsonl"
    builder_calls: list[int] = []

    def builder() -> Report:
        builder_calls.append(1)
        return _report(
            sections=[Section(id="gateway", title="网关", metrics=[_metric("latency", 3.0)])],
            score=Score(total=80, grade="B", items=[]),
        )

    samples = watch_cmd.run_watch(
        builder=builder,
        interval=5.0,
        count=3,
        engine=AlertEngine([], now=clock),
        out_path=out_path,
        sleep=sleeper,
        now=clock,
    )

    assert len(samples) == 3
    assert len(builder_calls) == 3
    assert sleeper.calls == [5.0, 5.0]

    records = history.load(out_path)
    assert len(records) == 3
    assert [record["kind"] for record in records] == ["watch", "watch", "watch"]
    assert [record["ts"] for record in records] == [sample.ts for sample in samples]
    assert [record["score"] for record in records] == [80, 80, 80]
    assert records[0]["metrics"] == [
        {
            "section": "gateway",
            "key": "latency",
            "label": "延迟",
            "value": 3.0,
            "unit": "ms",
            "available": True,
        }
    ]
    assert records[0]["alerts"] == []


def test_run_watch_count_zero_samples_nothing(tmp_path: Path) -> None:
    """count=0 不采样、不 sleep、不创建文件。"""
    out_path = tmp_path / "metrics.jsonl"
    sleeper = _Sleeper()

    samples = watch_cmd.run_watch(
        builder=lambda: _report(),
        count=0,
        out_path=out_path,
        sleep=sleeper,
        engine=AlertEngine([]),
    )

    assert samples == []
    assert sleeper.calls == []
    assert not out_path.exists()


def test_run_watch_defaults_to_metrics_jsonl_next_to_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未给 out_path 时写到 ``paths.history_path()`` 同目录的 metrics.jsonl。"""
    monkeypatch.setenv("NETOPT_HOME", str(tmp_path))
    clock = _Clock()

    samples = watch_cmd.run_watch(
        builder=lambda: _report(),
        count=1,
        engine=AlertEngine([], now=clock),
        sleep=_Sleeper(clock=clock),
        now=clock,
    )

    default_path = tmp_path / "state" / "metrics.jsonl"
    assert len(samples) == 1
    assert len(history.load(default_path)) == 1


# ---------------------------------------------------------------------------
# run_watch：停止条件
# ---------------------------------------------------------------------------
def test_run_watch_stops_after_event_set(tmp_path: Path) -> None:
    """第 2 次采样后置位 stop_event → 只留 2 个样本、只 sleep 1 次。"""
    clock = _Clock()
    sleeper = _Sleeper(clock=clock)
    event = _Event()
    builder_calls: list[int] = []

    def builder() -> Report:
        builder_calls.append(1)
        if len(builder_calls) == 2:
            event.set()
        return _report()

    samples = watch_cmd.run_watch(
        builder=builder,
        interval=1.0,
        count=None,
        engine=AlertEngine([], now=clock),
        out_path=tmp_path / "metrics.jsonl",
        sleep=sleeper,
        stop_event=event,
        now=clock,
    )

    assert len(samples) == 2
    assert len(builder_calls) == 2
    assert sleeper.calls == [1.0]


def test_run_watch_preset_event_samples_nothing(tmp_path: Path) -> None:
    """开始前 stop_event 已置位 → 零样本、零 sleep、零落盘。"""
    event = _Event()
    event.set()
    out_path = tmp_path / "metrics.jsonl"
    sleeper = _Sleeper()

    samples = watch_cmd.run_watch(
        builder=lambda: _report(),
        count=None,
        engine=AlertEngine([]),
        out_path=out_path,
        sleep=sleeper,
        stop_event=event,
    )

    assert samples == []
    assert sleeper.calls == []
    assert not out_path.exists()


# ---------------------------------------------------------------------------
# run_watch：告警冷却跨轮生效
# ---------------------------------------------------------------------------
def test_run_watch_alert_engine_cooldown_across_rounds(tmp_path: Path) -> None:
    """同一 finding 连续两轮只告警一次（默认冷却 300 秒，时钟只走 5 秒）。"""
    clock = _Clock()
    sleeper = _Sleeper(clock=clock)
    duplicate = [_finding("WAN_LATENCY_HIGH", Severity.critical)]

    samples = watch_cmd.run_watch(
        builder=lambda: _report(findings=duplicate),
        interval=5.0,
        count=2,
        engine=None,  # 交给 run_watch 用注入时钟创建并跨轮复用
        out_path=tmp_path / "metrics.jsonl",
        sleep=sleeper,
        now=clock,
    )

    assert [len(sample.alerts) for sample in samples] == [1, 0]
    assert sleeper.calls == [5.0]

    records = history.load(tmp_path / "metrics.jsonl")
    assert len(records[0]["alerts"]) == 1
    assert records[1]["alerts"] == []
    alert = records[0]["alerts"][0]
    assert alert == {
        "code": "WAN_LATENCY_HIGH",
        "severity": "critical",
        "title": "WAN_LATENCY_HIGH",
        "detail": "WAN_LATENCY_HIGH 的说明",
        "count": 1,
        "active": True,
    }


def test_run_watch_realerts_after_cooldown(tmp_path: Path) -> None:
    """时钟走过 300 秒冷却后再次出现 → 重新告警。

    ``count`` 的口径是「自上次通知以来的轮次」：每轮都恰好触发一次通知，
    因此三轮的 ``count`` 都是 1（冷却期内的累计已在上一轮清零）。
    """
    clock = _Clock()
    sleeper = _Sleeper(clock=clock)
    duplicate = [_finding("WAN_LATENCY_HIGH", Severity.critical)]

    samples = watch_cmd.run_watch(
        builder=lambda: _report(findings=duplicate),
        interval=300.0,
        count=3,
        engine=None,
        out_path=tmp_path / "metrics.jsonl",
        sleep=sleeper,
        now=clock,
    )

    assert [len(sample.alerts) for sample in samples] == [1, 1, 1]
    assert [sample.alerts[0].count for sample in samples] == [1, 1, 1]


# ---------------------------------------------------------------------------
# run_watch：写盘失败
# ---------------------------------------------------------------------------
def test_run_watch_records_write_error_and_continues(tmp_path: Path) -> None:
    """out_path 指向目录 → 每轮记一条 unavailable，循环照常跑满。"""
    broken = tmp_path / "as_dir"
    broken.mkdir()
    clock = _Clock()
    sleeper = _Sleeper(clock=clock)
    pre_existing = ProbeError(code=ProbeErrorCode.TIMEOUT.value, source="ping", message="超时")

    samples = watch_cmd.run_watch(
        builder=lambda: _report(
            findings=[_finding("WAN_UNREACHABLE")],
            errors=[pre_existing],
        ),
        interval=2.5,
        count=3,
        engine=None,  # 默认引擎：首轮告警，后续轮次处于冷却期
        out_path=broken,
        sleep=sleeper,
        now=clock,
    )

    assert len(samples) == 3
    assert sleeper.calls == [2.5, 2.5]
    for sample in samples:
        # 原有错误保留，写盘失败追加在末尾
        assert [error.code for error in sample.report.errors] == [
            ProbeErrorCode.TIMEOUT.value,
            ProbeErrorCode.UNAVAILABLE.value,
        ]
        error = sample.report.errors[-1]
        assert error.source == "watch"
        assert str(broken) in error.message
        assert error.retryable is True
    # 写盘失败不影响告警：首轮告警，后两轮在 300 秒冷却内
    assert [len(sample.alerts) for sample in samples] == [1, 0, 0]
    assert samples[0].alerts[0].code == "WAN_UNREACHABLE"


# ---------------------------------------------------------------------------
# 静默与参数校验
# ---------------------------------------------------------------------------
def test_run_watch_prints_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """命令层不打印：stdout / stderr 都必须为空。"""
    clock = _Clock()

    watch_cmd.run_watch(
        builder=lambda: _report(findings=[_finding()]),
        count=2,
        engine=AlertEngine([], now=clock),
        out_path=tmp_path / "metrics.jsonl",
        sleep=_Sleeper(clock=clock),
        now=clock,
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_run_watch_rejects_negative_count() -> None:
    """负的 count 是调用方错误，直接抛 ValueError。"""
    with pytest.raises(ValueError, match="count"):
        watch_cmd.run_watch(builder=lambda: _report(), count=-1)


def test_run_watch_rejects_negative_interval() -> None:
    """负的 interval 不能静默变成「不等待」，直接抛 ValueError。"""
    with pytest.raises(ValueError, match="interval"):
        watch_cmd.run_watch(builder=lambda: _report(), interval=-1.0)


# ---------------------------------------------------------------------------
# run_watch：流式回调与 collect=False
# ---------------------------------------------------------------------------
def test_run_watch_streams_each_round_without_collecting(tmp_path: Path) -> None:
    """collect=False → 不累积样本、返回值空，但每轮都回调且照常落盘。"""
    clock = _Clock()
    sleeper = _Sleeper(clock=clock)
    out_path = tmp_path / "metrics.jsonl"
    seen: list[watch_cmd.WatchSample] = []

    samples = watch_cmd.run_watch(
        builder=lambda: _report(score=Score(total=70, grade="C", items=[])),
        interval=5.0,
        count=3,
        engine=AlertEngine([], now=clock),
        out_path=out_path,
        sleep=sleeper,
        now=clock,
        on_sample=seen.append,
        collect=False,
    )

    assert samples == [], "collect=False 时不得累积样本（常驻采样不爆内存）"
    assert len(seen) == 3
    assert sleeper.calls == [5.0, 5.0], "轮数计数不能依赖已收集的列表"
    records = history.load(out_path)
    assert [record["ts"] for record in records] == [sample.ts for sample in seen]
    assert all(record["score"] == 70 for record in records)


def test_run_watch_collect_true_still_invokes_on_sample(tmp_path: Path) -> None:
    """collect=True 与 on_sample 可以同时使用，两者收到同一批样本。"""
    clock = _Clock()
    seen: list[str] = []

    samples = watch_cmd.run_watch(
        builder=lambda: _report(),
        interval=1.0,
        count=2,
        engine=AlertEngine([], now=clock),
        out_path=tmp_path / "metrics.jsonl",
        sleep=_Sleeper(clock=clock),
        now=clock,
        on_sample=lambda sample: seen.append(sample.ts),
    )

    assert [sample.ts for sample in samples] == seen


def test_run_watch_on_sample_receives_write_error_sample(tmp_path: Path) -> None:
    """写盘失败后回调拿到的样本必须带 ``unavailable`` 错误，不能是旧对象。"""
    broken = tmp_path / "as_dir"
    broken.mkdir()
    clock = _Clock()
    seen: list[watch_cmd.WatchSample] = []

    watch_cmd.run_watch(
        builder=lambda: _report(),
        count=1,
        engine=AlertEngine([], now=clock),
        out_path=broken,
        sleep=_Sleeper(clock=clock),
        now=clock,
        on_sample=seen.append,
        collect=False,
    )

    assert len(seen) == 1
    assert [error.code for error in seen[0].report.errors] == [ProbeErrorCode.UNAVAILABLE.value]
