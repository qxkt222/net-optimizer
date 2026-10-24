# -*- coding: utf-8 -*-
"""``netopt.commands.status`` 测试：读系统 → 测量 → 归因 → Report。

**绝不联网、绝不执行系统命令**：

- 系统读取一律注入 :class:`~netopt.system.api.FakeSystemApi`（路由与 DNS）；
- ping / MTU 类命令探测注入 ``conftest.fake_run`` 的真实抓取样本；
- MTU 需要按 payload 分支，``fake_run`` 的固定前缀匹配做不到，这里用同一批
  真实样本自行构造 runner（与 ``test_probes.py`` 同法）；
- DNS / HTTP 走 socket，测试一律注入假函数或由 Fake 驱动，不调用
  ``probes_dns`` / ``probes_http`` 的真实实现。
"""

from __future__ import annotations

import time

import pytest
from conftest import fixture_text

from netopt.commands import status as status_mod
from netopt.commands.status import build_status_report
from netopt.domain import FindingCode, InterfaceDns, ProbeErrorCode, Route, Severity
from netopt.models import PingStat
from netopt.platform import CmdResult
from netopt.render import render_plain
from netopt.system import FakeSystemApi

# MTU 探测用的真实样本（见 tests/fixtures/SOURCES.md）
_DF_OK = fixture_text("ping_df_ok")
_DF_FAIL = fixture_text("ping_df_fail")
_LOSS = fixture_text("ping_loss100")

_MTU_LIMIT = 1464  # 真实样本：1464 全通、1465 起 DF 失败 → MTU 1492

_GATEWAY_IP = "192.0.2.1"
_DNS_V4 = ["114.114.114.114", "192.0.2.1"]


def _mtu_run(*, limit: int = _MTU_LIMIT, upper: str = "df"):
    """按 ``-l`` payload 分支的假 ping（只用于 DF 探测）。"""

    def _run(argv, timeout=30.0, **kwargs):
        argv = list(argv)
        payload = int(argv[argv.index("-l") + 1])
        if payload <= limit:
            return CmdResult(argv=argv, code=0, out=_DF_OK.replace("1464", str(payload)))
        if upper == "timeout":
            return CmdResult(argv=argv, code=1, out=_LOSS)
        return CmdResult(argv=argv, code=1, out=_DF_FAIL.replace("1472", str(payload)))

    return _run


def _status_run(
    fake_run,
    *,
    ping_name: str = "ping_ok",
    ping_code: int = 0,
    mtu_limit: int = _MTU_LIMIT,
    mtu_upper: str = "df",
):
    """组合 ``fake_run``（普通 ping）与按 payload 分支的 MTU runner。"""
    fixed = fake_run({("ping",): (fixture_text(ping_name), ping_code)})
    mtu_run = _mtu_run(limit=mtu_limit, upper=mtu_upper)

    def run(argv, timeout=30.0, **kwargs):
        argv = list(argv)
        if argv and argv[0] == "ping" and "-f" in argv:
            return mtu_run(argv, timeout=timeout, **kwargs)
        return fixed(argv, timeout=timeout, **kwargs)

    return run


def _route(
    next_hop: str | None = _GATEWAY_IP,
    *,
    metric: int = 26,
    index: int = 2,
    is_default: bool = True,
) -> Route:
    """构造一条默认路由（字段与 ``netopt.domain.models.Route`` 对齐）。"""
    return Route(
        destination="0.0.0.0",
        prefix_len=0,
        next_hop=next_hop,
        interface_index=index,
        metric=metric,
        is_default=is_default,
    )


def _dns(servers: list[str], *, name: str = "以太网", index: int = 2) -> InterfaceDns:
    """构造一个接口的 DNS 配置。"""
    return InterfaceDns(
        adapter_index=index,
        interface_name=name,
        servers=list(servers),
        source="static",
    )


def _api(
    *,
    dns: list[InterfaceDns] | None = None,
    routes: list[Route] | None = None,
) -> FakeSystemApi:
    """默认给出「一条默认路由 + 两个 IPv4 DNS」，各测试按需覆盖。"""
    return FakeSystemApi(
        routes=[_route()] if routes is None else routes,
        dns_servers=[_dns(_DNS_V4)] if dns is None else dns,
    )


def _section(report, section_id: str):
    return next(section for section in report.sections if section.id == section_id)


def _metric(section, key: str):
    return next(metric for metric in section.metrics if metric.key == key)


def _codes(section) -> set[str]:
    return {finding.code for finding in section.findings}


def _top_codes(report) -> set[str]:
    return {finding.code for finding in report.findings}


# ===========================================================================
# 正常场景
# ===========================================================================
def test_status_normal_case_produces_five_sections_and_no_critical(fake_run) -> None:
    seen_dns: list[str] = []

    def dns_probe(server: str, host: str) -> float | None:
        seen_dns.append(server)
        return 20.0

    report = build_status_report(
        _status_run(fake_run),
        dns_probe=dns_probe,
        http_probe=lambda host: 120.0,
        api=_api(),
    )

    assert report.command == "status"
    assert report.schema_version == 1
    assert report.duration_ms >= 0
    assert [section.id for section in report.sections] == ["gateway", "wan", "dns", "http", "mtu"]
    assert {"admin", "python", "platform", "cwd", "api"} <= set(report.environment)
    assert report.environment["api"] == "iphlpapi"
    assert report.findings == []
    assert report.errors == []
    assert report.critical_findings() == []

    # 网关：延迟取 policy.gateway，丢包取 policy.loss；地址来自默认路由 next_hop
    gateway = _section(report, "gateway")
    latency = _metric(gateway, "latency")
    assert latency.value is not None and 20.0 <= latency.value <= 35.0
    assert (latency.good, latency.warn) == (5.0, 30.0)
    loss = _metric(gateway, "loss")
    assert loss.value == 0.0
    assert (loss.good, loss.warn) == (2.0, 50.0)
    assert gateway.rows == [{"ip": _GATEWAY_IP, "metric": 26}]
    assert gateway.findings == []

    # 外网：ping_ok 的 26 ms 在 wan.warn=100 以内，不产出结论
    wan = _section(report, "wan")
    assert _metric(wan, "latency").warn == 100.0
    assert wan.findings == []

    # DNS：只实测 IPv4 服务器，阈值来自 policy.dns
    dns = _section(report, "dns")
    dns_latency = _metric(dns, "latency")
    assert dns_latency.value == pytest.approx(20.0)
    assert (dns_latency.good, dns_latency.warn) == (30.0, 100.0)
    assert dns_latency.available is True
    assert dns.findings == []
    assert seen_dns == _DNS_V4, "只应实测前两台 IPv4 DNS"
    assert all(":" not in server for server in seen_dns), "IPv6 服务器不得进入 IPv4 实测"
    assert "114.114.114.114" in dns.rows[0]["servers"]

    # HTTP：TTFB 阈值来自 policy.http_ttfb
    http = _section(report, "http")
    http_metric = _metric(http, "ttfb")
    assert http_metric.value == pytest.approx(120.0)
    assert (http_metric.good, http_metric.warn) == (150.0, 500.0)
    assert http.findings == []

    # MTU：样本真值 1492 → PPPoE（info），且已验证
    mtu = _section(report, "mtu")
    assert _metric(mtu, "mtu").value == pytest.approx(1492.0)
    assert _codes(mtu) == {FindingCode.MTU_PPPOE}
    assert mtu.findings[0].severity is Severity.info


# ===========================================================================
# 不可达场景
# ===========================================================================
def test_status_unreachable_network_reports_critical_and_errors(fake_run) -> None:
    report = build_status_report(
        _status_run(
            fake_run, ping_name="ping_loss100", ping_code=1, mtu_limit=0, mtu_upper="timeout"
        ),
        dns_probe=lambda server, host: None,
        http_probe=lambda host: None,
        api=_api(),
    )

    gateway = _section(report, "gateway")
    assert _codes(gateway) == {FindingCode.GATEWAY_UNREACHABLE}
    assert gateway.findings[0].severity is Severity.critical
    assert _metric(gateway, "latency").available is False
    assert _metric(gateway, "loss").value == 100.0

    wan = _section(report, "wan")
    assert _codes(wan) == {FindingCode.WAN_UNREACHABLE}
    assert wan.findings[0].severity is Severity.critical

    dns = _section(report, "dns")
    assert _codes(dns) == {FindingCode.DNS_FAIL}
    assert _metric(dns, "latency").available is False

    http = _section(report, "http")
    assert _codes(http) == {FindingCode.HTTP_FAIL}
    assert _metric(http, "ttfb").value is None

    mtu = _section(report, "mtu")
    assert FindingCode.MTU_UNKNOWN in _codes(mtu)
    assert _metric(mtu, "mtu").available is False

    # 失败原因必须进 errors，不能吞成 None
    sources = {error.source for error in report.errors}
    assert "dns:114.114.114.114" in sources
    assert "dns:192.0.2.1" in sources
    assert "http:www.baidu.com" in sources
    assert "mtu" in sources
    assert all(error.retryable for error in report.errors if error.source.startswith("dns:"))
    assert len(report.critical_findings()) >= 4
    # 归因：网关不可达时根因落在本地链路
    assert FindingCode.DIAG_LOCAL_LINK in _top_codes(report)


# ===========================================================================
# 仅 IPv6 DNS（T3.4）
# ===========================================================================
def test_status_ipv6_only_dns_is_info_not_failure(fake_run) -> None:
    probed: list[str] = []

    def dns_probe(server: str, host: str) -> float | None:
        probed.append(server)
        return 15.0

    report = build_status_report(
        _status_run(fake_run),
        dns_probe=dns_probe,
        http_probe=lambda host: 100.0,
        api=_api(dns=[_dns(["fd00:db8::1", "fd00:db8::53"])]),
    )

    dns = _section(report, "dns")
    codes = _codes(dns)
    assert FindingCode.DNS_IPV6_ONLY in codes
    assert FindingCode.DNS_FAIL not in codes, "仅有 IPv6 DNS 不得误报解析失败"
    assert dns.findings[0].severity is Severity.info

    metric = _metric(dns, "latency")
    assert metric.available is False
    assert metric.note is not None and "IPv6" in metric.note
    assert probed == [], "没有 IPv4 DNS 时不得做 IPv4 实测"
    assert report.critical_findings() == []
    assert FindingCode.DIAG_DNS not in _top_codes(report), "IPv6-only 不应被归因为 DNS 故障"


# ===========================================================================
# 完全没有 DNS 配置
# ===========================================================================
def test_status_no_dns_config_is_warn(fake_run) -> None:
    report = build_status_report(
        _status_run(fake_run),
        dns_probe=lambda server, host: 1.0,
        http_probe=lambda host: 100.0,
        api=_api(dns=[]),
    )

    dns = _section(report, "dns")
    assert _codes(dns) == {FindingCode.DNS_NO_CONFIG}
    assert dns.findings[0].severity is Severity.warn
    assert _metric(dns, "latency").available is False
    assert report.critical_findings() == []


# ===========================================================================
# 延迟/丢包分档与 policy 一致
# ===========================================================================
def test_status_gateway_loss_finding_uses_policy_thresholds(fake_run) -> None:
    report = build_status_report(
        _status_run(fake_run, ping_name="ping_loss100", ping_code=1),
        dns_probe=lambda server, host: 10.0,
        http_probe=lambda host: 100.0,
        api=_api(),
    )

    gateway = _section(report, "gateway")
    # 100% 丢包达到 policy.loss.unusable=50 → critical，且同时报不可达
    assert FindingCode.GATEWAY_UNREACHABLE in _codes(gateway)
    assert _metric(gateway, "loss").warn == 50.0


def test_status_metric_thresholds_come_from_policy(fake_run) -> None:
    """命令层不得写死阈值：所有 metric 的 good/warn 必须与 Policy.default() 一致。"""
    from netopt.domain import Policy

    policy = Policy.default()
    report = build_status_report(
        _status_run(fake_run),
        dns_probe=lambda server, host: 20.0,
        http_probe=lambda host: 120.0,
        api=_api(),
    )

    gateway = _section(report, "gateway")
    assert _metric(gateway, "latency").good == policy.gateway.good
    assert _metric(gateway, "latency").warn == policy.gateway.warn
    assert _metric(gateway, "loss").good == policy.loss.tolerate
    assert _metric(_section(report, "wan"), "loss").warn == policy.loss.unusable
    assert _metric(_section(report, "dns"), "latency").warn == policy.dns.warn
    assert _metric(_section(report, "http"), "ttfb").warn == policy.http_ttfb.warn
    assert _metric(_section(report, "mtu"), "mtu").good == policy.mtu.standard


# ===========================================================================
# SystemApi 驱动：网关取 metric 最小的默认路由，DNS 取接口配置
# ===========================================================================
def test_status_gateway_and_dns_are_read_from_system_api(fake_run) -> None:
    routes = [
        _route("198.51.100.1", metric=9257, index=23),  # VPN 虚拟网卡（高 metric）
        _route(_GATEWAY_IP, metric=26, index=2),  # 真实默认路由
    ]
    report = build_status_report(
        _status_run(fake_run),
        dns_probe=lambda server, host: 20.0,
        http_probe=lambda host: 120.0,
        api=_api(routes=routes, dns=[_dns(["223.5.5.5"], name="WLAN", index=14)]),
    )

    gateway = _section(report, "gateway")
    assert gateway.rows == [{"ip": _GATEWAY_IP, "metric": 26}]
    assert _metric(gateway, "latency").available is True

    dns = _section(report, "dns")
    assert dns.rows == [{"servers": "223.5.5.5"}]

    # 没有默认路由 → 网关不可达，且失败必须可解释
    missing = build_status_report(
        _status_run(fake_run),
        dns_probe=lambda server, host: 20.0,
        http_probe=lambda host: 120.0,
        api=_api(routes=[]),
    )
    assert FindingCode.GATEWAY_UNREACHABLE in _codes(_section(missing, "gateway"))
    assert any(error.source == "iphlpapi" for error in missing.errors)


# ===========================================================================
# DNS 顺序：IPv6 排在前面也只实测 IPv4
# ===========================================================================
def test_status_dns_probes_only_ipv4_when_ipv6_comes_first(fake_run) -> None:
    seen: list[str] = []

    def dns_probe(server: str, host: str) -> float | None:
        seen.append(server)
        return 12.0

    report = build_status_report(
        _status_run(fake_run),
        dns_probe=dns_probe,
        http_probe=lambda host: 100.0,
        api=_api(dns=[_dns(["fd00:db8::1", "fd00:db8::53", "114.114.114.114", "192.0.2.1"])]),
    )

    assert seen == ["114.114.114.114", "192.0.2.1"]
    assert all(":" not in server for server in seen)
    dns = _section(report, "dns")
    assert _metric(dns, "latency").value == pytest.approx(12.0)
    assert FindingCode.DNS_FAIL not in _codes(dns)


# ===========================================================================
# ProbeContext 预算耗尽：不崩、错误可见
# ===========================================================================
def test_status_budget_exhaustion_records_timeout_without_raising(fake_run) -> None:
    def slow_dns(server: str, host: str) -> float | None:
        time.sleep(0.05)
        return 10.0

    report = build_status_report(
        _status_run(fake_run),
        dns_probe=slow_dns,
        http_probe=lambda host: 100.0,
        api=_api(),
        budget_seconds=0.01,
    )

    assert report.command == "status"
    assert [section.id for section in report.sections] == ["gateway", "wan", "dns", "http", "mtu"]
    assert any(error.code == ProbeErrorCode.TIMEOUT for error in report.errors)


# ===========================================================================
# 归因链：网关丢包 → DIAG_ACCESS_NETWORK
# ===========================================================================
def test_status_diagnose_reports_access_network_on_gateway_loss(
    fake_run, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_ping(target: str, count: int = 4, timeout_ms: int = 1000, run=None) -> PingStat:
        if target == _GATEWAY_IP:
            return PingStat(target=target, avg_ms=10.0, loss_pct=10.0, replies=3)
        return PingStat(target=target, avg_ms=26.0, loss_pct=0.0, replies=4)

    monkeypatch.setattr(status_mod.probes, "ping", fake_ping)

    report = build_status_report(
        _status_run(fake_run),
        dns_probe=lambda server, host: 20.0,
        http_probe=lambda host: 120.0,
        api=_api(),
    )

    assert FindingCode.DIAG_ACCESS_NETWORK in _top_codes(report)
    # 同一根因只保留一条归因结论
    assert len([f for f in report.findings if f.code == FindingCode.DIAG_ACCESS_NETWORK]) == 1
    assert report.findings[0].severity is Severity.warn


# ===========================================================================
# 渲染集成：rows 必须是扁平键，中文标签正确
# ===========================================================================
def test_status_rows_render_with_chinese_labels(fake_run) -> None:
    report = build_status_report(
        _status_run(fake_run),
        dns_probe=lambda server, host: 20.0,
        http_probe=lambda host: 120.0,
        api=_api(),
    )

    text = render_plain(report)
    for label in ("地址：", "跃点数：", "目标：", "服务器："):
        assert label in text, f"缺少中文标签 {label}"
    assert "key：" not in text, "rows 仍是 {key, value} 竖式结构"
    assert "value：" not in text, "rows 仍是 {key, value} 竖式结构"
