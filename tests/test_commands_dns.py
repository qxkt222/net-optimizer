# -*- coding: utf-8 -*-
"""``netopt.commands.dns`` 测试：公共 DNS + 系统 DNS 基准测试 → Report。

**绝不联网、绝不执行系统命令**：基准测试一律注入假 ``benchmark``；系统 DNS
读取注入 :class:`~netopt.system.api.FakeSystemApi`（或
``fake_run`` + ``netsh_dnsservers`` 真实样本）。预算耗尽用立即到期的上下文，
不 sleep。
"""

from __future__ import annotations

import pytest
from conftest import fixture_text

from netopt.commands.dns import DNS_ATTEMPTS, DNS_TEST_HOST, PUBLIC_DNS, build_dns_report
from netopt.domain import FindingCode, InterfaceDns, ProbeErrorCode, Severity
from netopt.probes_dns import DnsResult
from netopt.system import FakeSystemApi

_SYSTEM_DNS = "192.0.2.1"
_PUBLIC_ADDRESSES = [address for _, address in PUBLIC_DNS]


def _api(servers: tuple[str, ...] | list[str] = (_SYSTEM_DNS,), *, name: str = "以太网"):
    """默认给一个接口、一个 IPv4 DNS 服务器。"""
    return FakeSystemApi(
        dns_servers=[
            InterfaceDns(
                adapter_index=2,
                interface_name=name,
                servers=list(servers),
                source="static",
            )
        ]
    )


def _fake_benchmark(
    latencies: dict[str, float | None],
    calls: list[tuple[list[str], str, int]] | None = None,
):
    """按地址表返回 ``DnsResult``；``None`` 表示该服务器查询超时。"""

    def benchmark(servers, host, attempts: int = DNS_ATTEMPTS, ctx=None):
        if calls is not None:
            calls.append((list(servers), host, attempts))
        results = []
        for server in servers:
            elapsed = latencies.get(server, 20.0)
            if elapsed is None:
                results.append(
                    DnsResult(
                        server=server,
                        host=host,
                        elapsed_ms=None,
                        error="DNS 查询超时（udp）",
                        error_code=ProbeErrorCode.TIMEOUT.value,
                    )
                )
            else:
                results.append(
                    DnsResult(server=server, host=host, elapsed_ms=elapsed, transport="udp")
                )
        return results

    return benchmark


def _section(report, section_id: str):
    return next(section for section in report.sections if section.id == section_id)


def _metric(section, key: str):
    return next(metric for metric in section.metrics if metric.key == key)


def _codes(section) -> set[str]:
    return {finding.code for finding in section.findings}


def _row_by_address(section, address: str) -> dict:
    return next(row for row in section.rows if row["地址"] == address)


# ===========================================================================
# 正常场景
# ===========================================================================
def test_dns_normal_case_benchmarks_public_and_system_servers() -> None:
    latencies = {address: 10.0 + index for index, address in enumerate(_PUBLIC_ADDRESSES)}
    latencies[_SYSTEM_DNS] = 40.0
    calls: list[tuple[list[str], str, int]] = []

    report = build_dns_report(
        api=_api(),
        benchmark=_fake_benchmark(latencies, calls),
    )

    assert report.command == "dns"
    assert report.schema_version == 1
    assert report.duration_ms >= 0
    assert [section.id for section in report.sections] == ["dns"]
    assert report.findings == []
    assert report.errors == []

    # 7 台公共 DNS + 1 台系统 DNS，每台查 3 次
    assert len(calls) == 1
    servers, host, attempts = calls[0]
    assert host == DNS_TEST_HOST
    assert attempts == DNS_ATTEMPTS == 3
    assert servers == [*_PUBLIC_ADDRESSES, _SYSTEM_DNS]

    section = _section(report, "dns")
    assert len(section.rows) == 8
    addresses = [row["地址"] for row in section.rows]
    assert set(_PUBLIC_ADDRESSES) <= set(addresses)
    assert addresses[-1] == _SYSTEM_DNS, "系统 DNS 最慢，应排在最后"

    # 按耗时升序，且没有使用 key/value 竖式键
    elapsed = [row["耗时(ms)"] for row in section.rows]
    assert elapsed == sorted(elapsed)
    assert all("key" not in row and "value" not in row for row in section.rows)

    system_row = _row_by_address(section, _SYSTEM_DNS)
    assert system_row["来源"] == "系统"
    assert system_row["名称"] == "系统 DNS（以太网）"
    assert system_row["状态"] == "成功"

    latency = _metric(section, "latency")
    assert latency.value == pytest.approx(10.0)
    assert (latency.good, latency.warn) == (30.0, 100.0)
    assert latency.available is True
    assert section.findings == []


def test_dns_system_servers_are_deduped_against_public() -> None:
    calls: list[tuple[list[str], str, int]] = []

    report = build_dns_report(
        api=_api(("223.5.5.5", _SYSTEM_DNS)),
        benchmark=_fake_benchmark({}, calls),
    )

    servers = calls[0][0]
    assert servers.count("223.5.5.5") == 1
    assert _SYSTEM_DNS in servers
    section = _section(report, "dns")
    assert len(section.rows) == 8
    assert _row_by_address(section, "223.5.5.5")["来源"] == "公共"


# ===========================================================================
# 全失败
# ===========================================================================
def test_dns_all_servers_failing_is_critical_with_errors() -> None:
    latencies = dict.fromkeys([*_PUBLIC_ADDRESSES, _SYSTEM_DNS])

    report = build_dns_report(api=_api(), benchmark=_fake_benchmark(latencies))

    section = _section(report, "dns")
    assert _codes(section) == {FindingCode.DNS_FAIL}
    assert section.findings[0].severity is Severity.critical
    metric = _metric(section, "latency")
    assert metric.value is None
    assert metric.available is False
    assert metric.note is not None

    assert len(report.errors) == 8
    assert {error.source for error in report.errors} == {
        f"dns:{address}" for address in [*_PUBLIC_ADDRESSES, _SYSTEM_DNS]
    }
    assert all(error.code == ProbeErrorCode.TIMEOUT for error in report.errors)
    assert all(error.retryable for error in report.errors)


def test_dns_benchmark_exception_is_reported_not_raised() -> None:
    def benchmark(servers, host, attempts=DNS_ATTEMPTS, ctx=None):
        raise RuntimeError("基准测试崩溃")

    report = build_dns_report(api=_api(), benchmark=benchmark)

    section = _section(report, "dns")
    assert _codes(section) == {FindingCode.DNS_FAIL}
    assert section.findings[0].severity is Severity.critical
    assert _metric(section, "latency").available is False
    assert len(section.rows) == 8
    assert {row["状态"] for row in section.rows} == {"基准测试未完成"}

    assert [error.source for error in report.errors] == ["dns"]
    assert report.errors[0].code == ProbeErrorCode.UNAVAILABLE


# ===========================================================================
# 部分失败
# ===========================================================================
def test_dns_system_server_failure_is_warn_when_public_works() -> None:
    latencies = dict.fromkeys(_PUBLIC_ADDRESSES, 15.0)
    latencies[_SYSTEM_DNS] = None

    report = build_dns_report(api=_api(), benchmark=_fake_benchmark(latencies))

    section = _section(report, "dns")
    assert _codes(section) == {FindingCode.DNS_FAIL}
    assert section.findings[0].severity is Severity.warn
    assert "系统 DNS" in section.findings[0].title
    assert _metric(section, "latency").available is True

    assert [error.source for error in report.errors] == [f"dns:{_SYSTEM_DNS}"]
    failed_row = _row_by_address(section, _SYSTEM_DNS)
    assert failed_row["耗时(ms)"] is None
    assert "超时" in failed_row["状态"]
    assert section.rows[-1]["地址"] == _SYSTEM_DNS, "失败项应排在成功项之后"


def test_dns_single_public_failure_keeps_rows_and_reason() -> None:
    latencies = dict.fromkeys(_PUBLIC_ADDRESSES, 12.0)
    latencies["8.8.8.8"] = None
    latencies[_SYSTEM_DNS] = 25.0

    report = build_dns_report(api=_api(), benchmark=_fake_benchmark(latencies))

    section = _section(report, "dns")
    assert section.findings == [], "个别公共 DNS 失败不应把整条链路判成故障"
    assert _metric(section, "latency").value == pytest.approx(12.0)

    assert [error.source for error in report.errors] == ["dns:8.8.8.8"]
    assert report.errors[0].code == ProbeErrorCode.TIMEOUT
    failed_row = _row_by_address(section, "8.8.8.8")
    assert failed_row["状态"] == "DNS 查询超时（udp）"
    assert section.rows[-1]["地址"] == "8.8.8.8"


# ===========================================================================
# 系统 DNS 缺失 / 读取失败
# ===========================================================================
def test_dns_no_system_config_is_warn_but_public_benchmark_still_runs() -> None:
    calls: list[tuple[list[str], str, int]] = []

    report = build_dns_report(
        api=FakeSystemApi(),
        benchmark=_fake_benchmark({}, calls),
    )

    section = _section(report, "dns")
    assert _codes(section) == {FindingCode.DNS_NO_CONFIG}
    assert section.findings[0].severity is Severity.warn
    assert calls[0][0] == _PUBLIC_ADDRESSES
    assert len(section.rows) == 7


def test_dns_system_config_read_failure_is_reported_but_public_dns_works() -> None:
    class _BrokenApi:
        def dns_servers(self):
            raise RuntimeError("iphlpapi 不可用")

    report = build_dns_report(
        api=_BrokenApi(),  # type: ignore[arg-type]
        benchmark=_fake_benchmark({}),
    )

    section = _section(report, "dns")
    assert _metric(section, "latency").available is True
    assert FindingCode.DNS_NO_CONFIG not in _codes(section)
    assert [error.source for error in report.errors] == ["iphlpapi"]
    assert report.errors[0].code == ProbeErrorCode.UNAVAILABLE


# ===========================================================================
# 旧路径：显式注入 run 时经 netsh 读取系统 DNS
# ===========================================================================
def test_dns_reads_system_config_from_injected_runner(fake_run) -> None:
    run = fake_run(
        {
            ("netsh", "interface", "ipv4", "show", "dnsservers"): (
                fixture_text("netsh_dnsservers"),
                0,
            )
        }
    )
    calls: list[tuple[list[str], str, int]] = []

    report = build_dns_report(run=run, benchmark=_fake_benchmark({}, calls))

    assert report.environment["api"] == "netsh"
    assert _SYSTEM_DNS in calls[0][0]
    section = _section(report, "dns")
    system_row = _row_by_address(section, _SYSTEM_DNS)
    assert system_row["来源"] == "系统"
    assert system_row["名称"] == "系统 DNS（以太网）"


# ===========================================================================
# 慢速与预算
# ===========================================================================
def test_dns_slow_servers_use_policy_band() -> None:
    latencies = dict.fromkeys([*_PUBLIC_ADDRESSES, _SYSTEM_DNS], 150.0)

    report = build_dns_report(api=_api(), benchmark=_fake_benchmark(latencies))

    section = _section(report, "dns")
    assert _codes(section) == {FindingCode.DNS_SLOW}
    # policy.dns: good=30 warn=100 poor=200 → 150 落在 warn 档
    assert section.findings[0].severity is Severity.warn
    assert _metric(section, "latency").value == pytest.approx(150.0)


def test_dns_budget_exhaustion_skips_benchmark_without_sleeping() -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("预算已耗尽时不应启动基准测试")

    report = build_dns_report(api=_api(), benchmark=forbidden, budget_seconds=0.0)

    section = _section(report, "dns")
    assert _metric(section, "latency").available is False
    assert _codes(section) == {FindingCode.DNS_FAIL}
    assert [error.source for error in report.errors] == ["dns"]
    assert report.errors[0].code == ProbeErrorCode.TIMEOUT
    assert {row["状态"] for row in section.rows} == {"基准测试未完成"}
