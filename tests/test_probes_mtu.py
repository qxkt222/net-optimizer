# -*- coding: utf-8 -*-
"""probes_mtu 测试：预算内二分、边界确认、超时提前返回。

不执行任何真实 ping：runner 一律按 ``-l`` payload 分支返回 fixtures 里的
真实样本。预算用例用**可控时钟**（runner 每跑一次就前进固定步长）验证
「到期立即停止」，不依赖真实时间，CI 上不会因机器慢而抖动。
"""

from __future__ import annotations

from conftest import fixture_text

from netopt.platform import CmdResult
from netopt.probes import ProbeContext
from netopt.probes_mtu import probe

_DF_OK = fixture_text("ping_df_ok")  # 真实样本：payload 1464 通
_DF_FAIL = fixture_text("ping_df_fail")  # 真实样本：payload 1472 报 DF
_LOSS = fixture_text("ping_loss100")  # 真实样本：请求超时（不确定信号）

_MTU_LIMIT = 1464  # 本机真值：1464 全通、1465 起不通 → MTU 1492


class _Clock:
    """可控时钟：替身 ``time.monotonic``，让预算用例完全确定。"""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _payload_of(argv: list[str]) -> int:
    return int(argv[argv.index("-l") + 1])


def _mtu_runner(
    *,
    limit: int = _MTU_LIMIT,
    upper: str = "df",
    first_uncertain: bool = False,
    clock: _Clock | None = None,
    advance: float = 0.0,
):
    """按 payload 分支的假 ping。

    ``limit`` 及以下返回「通」；以上按 ``upper`` 返回 DF 失败（``"df"``）
    或超时（``"timeout"``，不确定信号）。传入 ``clock`` 时，每执行一次
    假 ping 就把它前进 ``advance`` 秒，模拟慢链路。
    """
    calls: list[list[str]] = []
    timeouts: list[float] = []
    seen_first = False

    def _run(argv, timeout=30.0, **kwargs):
        nonlocal seen_first
        argv = list(argv)
        calls.append(argv)
        timeouts.append(timeout)
        if clock is not None:
            clock.advance(advance)
        payload = _payload_of(argv)
        if first_uncertain and not seen_first:
            seen_first = True
            return CmdResult(argv=argv, code=1, out=_LOSS)
        if payload <= limit:
            return CmdResult(argv=argv, code=0, out=_DF_OK.replace("1464", str(payload)))
        if upper == "timeout":
            return CmdResult(argv=argv, code=1, out=_LOSS)
        return CmdResult(argv=argv, code=1, out=_DF_FAIL.replace("1472", str(payload)))

    _run.calls = calls  # type: ignore[attr-defined]
    _run.timeouts = timeouts  # type: ignore[attr-defined]
    return _run


def test_probe_finds_pppoe_1492() -> None:
    """本机真值 MTU=1492（payload 1464 通 / 1465 不通）必须稳定得出。"""
    ctx = ProbeContext.with_budget(30.0)
    run = _mtu_runner()
    result = probe(ctx=ctx, run=run)

    assert result.payload == 1464
    assert result.mtu == 1492
    assert result.verified is True
    assert result.is_pppoe() is True
    assert len(run.calls) <= 25, f"探测次数过多: {len(run.calls)}"
    assert ctx.errors == []


def test_probe_standard_ethernet_when_all_pass() -> None:
    """全程可通（标准以太网 1500）：报 1500 且 verified=True。"""
    result = probe(ctx=ProbeContext.with_budget(30.0), run=_mtu_runner(limit=1472))

    assert result.payload == 1472
    assert result.mtu == 1500
    assert result.verified is True
    assert result.is_standard_ethernet() is True


def test_probe_retries_uncertain_probe() -> None:
    """首次返回超时（不确定）时必须重试同一 payload，而不是当成失败。"""
    run = _mtu_runner(first_uncertain=True)
    result = probe(ctx=ProbeContext.with_budget(30.0), run=run)

    assert result.mtu == 1492
    assert result.verified is True
    assert len(run.calls) >= 2
    assert run.calls[0] == run.calls[1], "不确定结果没有重试同一点位"


def test_probe_upper_timeout_is_not_a_pass() -> None:
    """上界是超时（不确定）时不能当通过；结果保留但 verified=False。"""
    result = probe(ctx=ProbeContext.with_budget(30.0), run=_mtu_runner(upper="timeout"))

    assert result.payload == 1464
    assert result.mtu == 1492
    assert result.verified is False


def test_probe_unreachable_returns_empty_and_bails_early() -> None:
    """连最小 payload 都不通：返回全 None，且尽早退出。"""
    run = _mtu_runner(limit=0, upper="timeout")
    result = probe(ctx=ProbeContext.with_budget(30.0), run=run)

    assert result.found is False
    assert result.mtu is None
    assert result.payload is None
    assert len(run.calls) <= 4, "不可达时应尽早退出"


def test_probe_ping_missing_returns_empty() -> None:
    """ping 命令不存在：拿不到确定信号，返回全 None。"""
    calls: list[list[str]] = []

    def _run(argv, timeout=30.0, **kwargs):
        argv = list(argv)
        calls.append(argv)
        return CmdResult(argv=argv, code=-1, out="找不到命令：ping", missing=True)

    result = probe(ctx=ProbeContext.with_budget(30.0), run=_run)

    assert result.found is False
    assert len(calls) <= 4


def test_probe_zero_budget_returns_empty_with_timeout_error() -> None:
    """上下文预算已耗尽：不发任何 ping，直接返回并记 timeout。"""
    ctx = ProbeContext.with_budget(0.0)
    calls: list[list[str]] = []

    def _run(argv, timeout=30.0, **kwargs):
        calls.append(list(argv))
        return CmdResult(argv=list(argv), code=0, out=_DF_OK)

    result = probe(ctx=ctx, run=_run)

    assert result.found is False
    assert calls == [], "预算已耗尽却仍然发了 ping"
    assert [err.code for err in ctx.errors] == ["timeout"]
    assert ctx.errors[0].source == "mtu"
    assert ctx.errors[0].retryable is True


def test_probe_tiny_deadline_stops_after_slow_ping(monkeypatch) -> None:
    """deadline 极小 + 每次 ping 都慢：第一次之后立即停，结果未验证。"""
    clock = _Clock()
    monkeypatch.setattr("netopt.probes_mtu.time", clock)
    ctx = ProbeContext.with_budget(30.0)
    run = _mtu_runner(clock=clock, advance=0.15)
    result = probe(ctx=ctx, run=run, max_seconds=0.05)

    assert result.verified is False
    assert result.found is False
    assert len(run.calls) == 1, "预算到期后不应再发新的 ping"
    assert [err.code for err in ctx.errors] == ["timeout"]


def test_probe_ping_timeout_never_exceeds_remaining_budget(monkeypatch) -> None:
    """单次 ping 的 timeout 收敛到剩余预算内，且永不超过 5 秒。"""
    clock = _Clock()
    monkeypatch.setattr("netopt.probes_mtu.time", clock)
    ctx = ProbeContext.with_budget(30.0)
    run = _mtu_runner(clock=clock, advance=0.2)
    probe(ctx=ctx, run=run, max_seconds=0.05)

    assert run.timeouts, "没有记录到 ping 的 timeout 参数"
    assert 0.0 < run.timeouts[0] <= 0.05, f"timeout 越过剩余预算: {run.timeouts[0]}"
    assert run.timeouts[0] <= 5.0


def test_probe_deadline_keeps_partial_result(monkeypatch) -> None:
    """预算在二分途中耗尽：返回已确认的最大 payload + verified=False。"""
    clock = _Clock()
    monkeypatch.setattr("netopt.probes_mtu.time", clock)
    ctx = ProbeContext.with_budget(30.0)
    run = _mtu_runner(clock=clock, advance=0.03)
    result = probe(ctx=ctx, run=run, max_seconds=0.25)

    assert result.found is True, "已有确定通过的点位却返回了全 None"
    assert result.payload is not None and result.payload <= 1472
    assert result.mtu == result.payload + 28
    assert result.verified is False
    assert [err.code for err in ctx.errors] == ["timeout"]


def test_probe_does_not_print(capsys) -> None:
    """探测层不打印任何东西（展示是渲染层的职责）。"""
    probe(ctx=ProbeContext.with_budget(30.0), run=_mtu_runner())
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
