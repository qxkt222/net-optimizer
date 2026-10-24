# -*- coding: utf-8 -*-
"""``netopt.commands.http`` 测试：4 站点 HTTPS 测量 → Report。

**绝不联网**：``measure`` 一律注入假函数，返回构造的
:class:`~netopt.probes_http.HttpTiming`；预算耗尽用立即到期的上下文，
不 sleep。
"""

from __future__ import annotations

import pytest

from netopt.commands.http import SITES, build_http_report
from netopt.domain import FindingCode, Policy, ProbeErrorCode, Severity
from netopt.probes_http import HttpTiming

_HOSTS = [host for _, host in SITES]


def _timing(host: str, ttfb: float = 120.0, *, status: int = 200) -> HttpTiming:
    """构造一次成功的四段计时。"""
    return HttpTiming(
        host=host,
        connect_ms=10.0,
        tls_ms=20.0,
        ttfb_ms=ttfb,
        total_ms=ttfb + 5.0,
        status=status,
    )


def _measure(values: dict[str, object], calls: list[str] | None = None):
    """按域名返回预设结果：数字成功、``None`` 超时、异常则抛出。"""

    def measure(host: str):
        if calls is not None:
            calls.append(host)
        value = values.get(host, 120.0)
        if isinstance(value, Exception):
            raise value
        if value is None:
            return HttpTiming(
                host=host,
                error="HTTP 探测超时：timed out",
                error_code=ProbeErrorCode.TIMEOUT.value,
            )
        if isinstance(value, HttpTiming):
            return value
        return _timing(host, float(value))

    return measure


def _section(report, section_id: str):
    return next(section for section in report.sections if section.id == section_id)


def _metric(section, key: str):
    return next(metric for metric in section.metrics if metric.key == key)


def _codes(section) -> set[str]:
    return {finding.code for finding in section.findings}


def _row(section, host: str) -> dict:
    return next(row for row in section.rows if row["域名"] == host)


# ===========================================================================
# 正常场景
# ===========================================================================
def test_http_normal_case_measures_all_sites() -> None:
    calls: list[str] = []
    ttfb_values = {host: 100.0 + index * 50 for index, host in enumerate(_HOSTS)}

    report = build_http_report(measure=_measure(ttfb_values, calls))

    assert report.command == "http"
    assert report.schema_version == 1
    assert report.duration_ms >= 0
    assert [section.id for section in report.sections] == ["http"]
    assert report.findings == []
    assert report.errors == []
    assert report.critical_findings() == []
    assert calls == _HOSTS

    section = _section(report, "http")
    assert len(section.rows) == 4
    first = _row(section, "www.baidu.com")
    assert first["站点"] == "百度"
    assert first["状态码"] == 200
    assert first["TTFB(ms)"] == pytest.approx(100.0)
    assert first["状态"] == "成功"

    metric = _metric(section, "ttfb")
    assert metric.value == pytest.approx(100.0)
    assert (metric.good, metric.warn) == (150.0, 500.0)
    assert metric.available is True
    assert section.findings == []


def test_http_metric_thresholds_come_from_policy() -> None:
    policy = Policy.default()

    report = build_http_report(measure=_measure(dict.fromkeys(_HOSTS, 100.0)))

    metric = _metric(_section(report, "http"), "ttfb")
    assert metric.good == policy.http_ttfb.good
    assert metric.warn == policy.http_ttfb.warn


def test_http_falls_back_to_total_when_ttfb_is_missing() -> None:
    timing = HttpTiming(host=_HOSTS[0], total_ms=120.0, status=200)

    report = build_http_report(
        measure=_measure({_HOSTS[0]: timing, **dict.fromkeys(_HOSTS[1:], 80.0)})
    )

    assert _row(_section(report, "http"), _HOSTS[0])["TTFB(ms)"] == pytest.approx(120.0)
    assert _metric(_section(report, "http"), "ttfb").value == pytest.approx(80.0)


# ===========================================================================
# 全失败
# ===========================================================================
def test_http_all_sites_failing_is_critical_with_errors() -> None:
    report = build_http_report(measure=_measure(dict.fromkeys(_HOSTS)))

    section = _section(report, "http")
    assert _codes(section) == {FindingCode.HTTP_FAIL}
    assert section.findings[0].severity is Severity.critical
    metric = _metric(section, "ttfb")
    assert metric.value is None
    assert metric.available is False
    assert metric.note is not None

    assert {error.source for error in report.errors} == {f"http:{host}" for host in _HOSTS}
    assert len(report.errors) == 4
    assert all(error.code == ProbeErrorCode.TIMEOUT for error in report.errors)
    assert all(error.retryable for error in report.errors)
    assert all("超时" in row["状态"] for row in section.rows)
    assert len(report.critical_findings()) == 1


# ===========================================================================
# 部分失败
# ===========================================================================
def test_http_partial_failure_is_warn_and_keeps_reason() -> None:
    values = dict.fromkeys(_HOSTS, 110.0)
    values["www.microsoft.com"] = RuntimeError("连接被重置")

    report = build_http_report(measure=_measure(values))

    section = _section(report, "http")
    assert _codes(section) == {FindingCode.HTTP_FAIL}
    assert section.findings[0].severity is Severity.warn
    assert "1/4" in section.findings[0].detail

    metric = _metric(section, "ttfb")
    assert metric.value == pytest.approx(110.0)
    assert metric.available is True

    assert [error.source for error in report.errors] == ["http:www.microsoft.com"]
    assert report.errors[0].code == ProbeErrorCode.UNAVAILABLE
    failed = _row(section, "www.microsoft.com")
    assert "连接被重置" in failed["状态"]
    assert failed["状态码"] is None


# ===========================================================================
# 慢速与预算
# ===========================================================================
def test_http_slow_sites_use_policy_band() -> None:
    report = build_http_report(measure=_measure(dict.fromkeys(_HOSTS, 800.0)))

    section = _section(report, "http")
    assert _codes(section) == {FindingCode.HTTP_SLOW}
    # policy.http_ttfb: good=150 warn=500 poor=1000 → 800 落在 warn 档
    assert section.findings[0].severity is Severity.warn
    assert _metric(section, "ttfb").value == pytest.approx(800.0)


def test_http_budget_exhaustion_skips_measure_without_sleeping() -> None:
    def forbidden(host):
        raise AssertionError("预算已耗尽时不应发起 HTTP 请求")

    report = build_http_report(measure=forbidden, budget_seconds=0.0)

    section = _section(report, "http")
    assert _metric(section, "ttfb").available is False
    assert _codes(section) == {FindingCode.HTTP_FAIL}
    assert {error.source for error in report.errors} == {f"http:{host}" for host in _HOSTS}
    assert {error.code for error in report.errors} == {ProbeErrorCode.TIMEOUT}
    assert {row["状态"] for row in section.rows} == {"预算已耗尽"}
