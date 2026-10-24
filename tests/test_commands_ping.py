# -*- coding: utf-8 -*-
"""``netopt.commands.ping`` 测试：网关 + 目标 ping → Report。

**绝不执行系统命令**：ping 一律注入 ``conftest.fake_run`` 的真实抓取样本，
系统读取注入 :class:`~netopt.system.api.FakeSystemApi`；预算耗尽场景用
立即到期的上下文，不 sleep、不碰网络。
"""

from __future__ import annotations

import pytest
from conftest import fixture_text

from netopt.commands import ping as ping_mod
from netopt.commands.ping import DEFAULT_TARGET, build_ping_report
from netopt.domain import FindingCode, Policy, ProbeErrorCode, Route, Severity
from netopt.models import PingStat
from netopt.system import FakeSystemApi

_GATEWAY_IP = "192.0.2.1"


def _route(
    next_hop: str | None = _GATEWAY_IP,
    *,
    metric: int = 26,
    index: int = 2,
) -> Route:
    """构造一条默认路由（字段与 ``netopt.domain.models.Route`` 对齐）。"""
    return Route(
        destination="0.0.0.0",
        prefix_len=0,
        next_hop=next_hop,
        interface_index=index,
        metric=metric,
        is_default=True,
    )


def _api(*, routes: list[Route] | None = None) -> FakeSystemApi:
    """默认给出「metric 最小的默认路由」；传空列表模拟无默认路由。"""
    return FakeSystemApi(routes=[_route()] if routes is None else routes)


def _section(report, section_id: str):
    return next(section for section in report.sections if section.id == section_id)


def _metric(section, key: str):
    return next(metric for metric in section.metrics if metric.key == key)


def _codes(section) -> set[str]:
    return {finding.code for finding in section.findings}


# ===========================================================================
# 正常场景
# ===========================================================================
def test_ping_normal_case_has_gateway_and_target_sections(fake_run) -> None:
    run = fake_run({("ping",): (fixture_text("ping_ok"), 0)})

    report = build_ping_report(run=run, api=_api())

    assert report.command == "ping"
    assert report.schema_version == 1
    assert report.duration_ms >= 0
    assert [section.id for section in report.sections] == ["gateway", "target"]
    assert {"admin", "python", "platform", "cwd", "api"} <= set(report.environment)
    assert report.environment["api"] == "iphlpapi"
    assert report.environment["target"] == DEFAULT_TARGET
    assert report.findings == []
    assert report.errors == []
    assert report.critical_findings() == []

    # 网关：延迟取 policy.gateway，丢包取 policy.loss；地址来自默认路由 next_hop
    gateway = _section(report, "gateway")
    latency = _metric(gateway, "latency")
    assert latency.value == pytest.approx(26.0, abs=1.0)
    assert (latency.good, latency.warn) == (5.0, 30.0)
    loss = _metric(gateway, "loss")
    assert loss.value == 0.0
    assert (loss.good, loss.warn) == (2.0, 50.0)
    assert gateway.rows == [{"ip": _GATEWAY_IP, "metric": 26}]
    assert gateway.findings == []

    # 目标：默认 www.baidu.com，26 ms 在 wan.warn=100 以内，不产出结论
    target = _section(report, "target")
    target_latency = _metric(target, "latency")
    assert target_latency.available is True
    assert target_latency.warn == 100.0
    assert target.rows == [{"target": DEFAULT_TARGET}]
    assert target.findings == []


def test_ping_respects_explicit_target(fake_run) -> None:
    run = fake_run({("ping",): (fixture_text("ping_ok"), 0)})

    report = build_ping_report("example.test", run=run, api=_api())

    target = _section(report, "target")
    assert target.rows == [{"target": "example.test"}]
    assert report.environment["target"] == "example.test"


def test_ping_metrics_thresholds_come_from_policy(fake_run) -> None:
    """命令层不得写死阈值：所有 metric 的 good/warn 必须与 Policy.default() 一致。"""
    policy = Policy.default()
    run = fake_run({("ping",): (fixture_text("ping_ok"), 0)})

    report = build_ping_report(run=run, api=_api())

    gateway = _section(report, "gateway")
    assert _metric(gateway, "latency").good == policy.gateway.good
    assert _metric(gateway, "latency").warn == policy.gateway.warn
    assert _metric(gateway, "loss").good == policy.loss.tolerate
    assert _metric(gateway, "loss").warn == policy.loss.unusable
    target = _section(report, "target")
    assert _metric(target, "latency").good == policy.wan.good
    assert _metric(target, "latency").warn == policy.wan.warn


# ===========================================================================
# 全失败：目标不可达（有统计、无回复）
# ===========================================================================
def test_ping_unreachable_produces_critical_findings(fake_run) -> None:
    run = fake_run({("ping",): (fixture_text("ping_loss100"), 1)})

    report = build_ping_report(run=run, api=_api())

    gateway = _section(report, "gateway")
    assert _codes(gateway) == {FindingCode.GATEWAY_UNREACHABLE}
    assert gateway.findings[0].severity is Severity.critical
    assert _metric(gateway, "latency").available is False
    assert _metric(gateway, "loss").value == 100.0

    target = _section(report, "target")
    assert _codes(target) == {FindingCode.WAN_UNREACHABLE}
    assert target.findings[0].severity is Severity.critical
    # probes.ping 正常返回了统计，这属于“主机不可达”而非“探测失败”
    assert report.errors == []
    assert len(report.critical_findings()) == 2


# ===========================================================================
# 全失败：探测本身抛异常
# ===========================================================================
def test_ping_probe_exception_records_errors_without_crashing() -> None:
    def boom(argv, timeout=30.0, **kwargs):
        raise RuntimeError("ping 执行失败")

    report = build_ping_report(run=boom, api=_api())

    for section_id in ("gateway", "target"):
        section = _section(report, section_id)
        assert _metric(section, "latency").available is False
        assert _metric(section, "loss").available is False
        assert section.findings == []

    assert {error.source for error in report.errors} == {
        f"ping:{_GATEWAY_IP}",
        f"ping:{DEFAULT_TARGET}",
    }
    assert all(error.code == ProbeErrorCode.UNAVAILABLE for error in report.errors)


# ===========================================================================
# 部分失败：网关正常、目标探测异常
# ===========================================================================
def test_ping_partial_failure_keeps_gateway_section(fake_run) -> None:
    fixed = fake_run({("ping",): (fixture_text("ping_ok"), 0)})

    def run(argv, timeout=30.0, **kwargs):
        if DEFAULT_TARGET in argv:
            raise RuntimeError("目标探测失败")
        return fixed(argv, timeout=timeout, **kwargs)

    report = build_ping_report(run=run, api=_api())

    gateway = _section(report, "gateway")
    assert _metric(gateway, "latency").available is True
    assert gateway.findings == []

    target = _section(report, "target")
    assert _metric(target, "latency").available is False
    assert target.findings == []

    assert [error.source for error in report.errors] == [f"ping:{DEFAULT_TARGET}"]
    assert report.errors[0].code == ProbeErrorCode.UNAVAILABLE


# ===========================================================================
# 没有默认网关
# ===========================================================================
def test_ping_missing_gateway_is_critical_but_target_still_measured(fake_run) -> None:
    run = fake_run({("ping",): (fixture_text("ping_ok"), 0)})

    report = build_ping_report(run=run, api=_api(routes=[]))

    gateway = _section(report, "gateway")
    assert _codes(gateway) == {FindingCode.GATEWAY_UNREACHABLE}
    assert gateway.findings[0].severity is Severity.critical
    assert _metric(gateway, "latency").available is False
    assert any(error.source == "iphlpapi" for error in report.errors)

    target = _section(report, "target")
    assert _metric(target, "latency").available is True
    assert not [error for error in report.errors if error.source.startswith("ping:")], (
        "没有网关时不该 ping 网关；目标 ping 成功也不该有探测错误"
    )


# ===========================================================================
# 延迟 / 丢包分档与 policy 一致
# ===========================================================================
def test_ping_findings_follow_policy_thresholds(fake_run, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_ping(target: str, count: int = 4, timeout_ms: int = 1000, run=None) -> PingStat:
        if target == _GATEWAY_IP:
            # 10% 丢包 + 60 ms 延迟：丢包 warn，延迟超过 poor=50 → critical
            return PingStat(target=target, avg_ms=60.0, loss_pct=10.0, replies=3)
        # 200 ms 超过 wan.poor=150 → critical
        return PingStat(target=target, avg_ms=200.0, loss_pct=0.0, replies=4)

    monkeypatch.setattr(ping_mod.probes, "ping", fake_ping)

    report = build_ping_report(
        run=fake_run({("ping",): (fixture_text("ping_ok"), 0)}),
        api=_api(),
    )

    gateway = _section(report, "gateway")
    assert _codes(gateway) == {FindingCode.GATEWAY_LOSS, FindingCode.GATEWAY_LATENCY_HIGH}
    severities = {finding.code: finding.severity for finding in gateway.findings}
    assert severities[FindingCode.GATEWAY_LOSS] is Severity.warn
    assert severities[FindingCode.GATEWAY_LATENCY_HIGH] is Severity.critical

    target = _section(report, "target")
    assert _codes(target) == {FindingCode.WAN_LATENCY_HIGH}
    assert target.findings[0].severity is Severity.critical


# ===========================================================================
# ProbeContext 预算耗尽：不执行探测、不崩、错误可见
# ===========================================================================
def test_ping_budget_exhaustion_skips_probes_without_sleeping() -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("预算已耗尽时不应执行 ping")

    report = build_ping_report(run=forbidden, api=_api(), budget_seconds=0.0)

    assert [section.id for section in report.sections] == ["gateway", "target"]
    assert {error.code for error in report.errors} == {ProbeErrorCode.TIMEOUT}
    assert {error.source for error in report.errors} == {
        f"ping:{_GATEWAY_IP}",
        f"ping:{DEFAULT_TARGET}",
    }
    assert all(error.retryable for error in report.errors)
    assert _metric(_section(report, "gateway"), "latency").available is False
    assert _metric(_section(report, "target"), "loss").available is False
