# -*- coding: utf-8 -*-
"""``netopt.commands.speed`` 测试：3 下载源 + 1 上传源 → Report。

**绝不联网**：``download`` / ``upload`` 一律注入假函数，返回构造的
:class:`~netopt.probes_speed.SpeedResult`；预算耗尽用立即到期的上下文，
不 sleep。
"""

from __future__ import annotations

import pytest

from netopt.commands.speed import (
    DOWNLOAD_SOURCES,
    SPEED_FAIL,
    UPLOAD_SOURCE,
    build_speed_report,
)
from netopt.domain import ProbeErrorCode, Severity
from netopt.probes_speed import SpeedResult

_DOWNLOAD_NAMES = [name for name, _ in DOWNLOAD_SOURCES]
_UPLOAD_NAME = UPLOAD_SOURCE[0]


def _fake_download(values: dict[str, object], calls: list[tuple[str, str, dict]] | None = None):
    """按源名返回预设结果：数字成功、``None`` 失败、异常则抛出。"""

    def download(name: str, url: str, **kwargs):
        if calls is not None:
            calls.append((name, url, kwargs))
        value = values.get(name, 100.0)
        if isinstance(value, Exception):
            raise value
        if value is None:
            return SpeedResult(name=name, mbps=None, error="连接超时")
        if isinstance(value, SpeedResult):
            return value
        return SpeedResult(name=name, mbps=float(value), bytes=1024, seconds=1.0)

    return download


def _fake_upload(value: object, calls: list[tuple[str, str, dict]] | None = None):
    """上传源替身：默认 50 Mbps，``None`` 表示失败。"""

    def upload(name: str, url: str, **kwargs):
        if calls is not None:
            calls.append((name, url, kwargs))
        if isinstance(value, Exception):
            raise value
        if value is None:
            return SpeedResult(name=name, mbps=None, error="上传连接被重置")
        if isinstance(value, SpeedResult):
            return value
        return SpeedResult(name=name, mbps=float(value), bytes=1024, seconds=1.0)

    return upload


def _section(report, section_id: str):
    return next(section for section in report.sections if section.id == section_id)


def _metric(section, key: str):
    return next(metric for metric in section.metrics if metric.key == key)


def _codes(section) -> set[str]:
    return {finding.code for finding in section.findings}


def _row(section, name: str) -> dict:
    return next(row for row in section.rows if row["源"] == name)


# ===========================================================================
# 正常场景
# ===========================================================================
def test_speed_normal_case_reports_best_download_and_upload() -> None:
    calls: list[tuple[str, str, dict]] = []
    downloads = {"Cloudflare": 100.0, "阿里云镜像": 300.0, "清华镜像": 200.0}

    report = build_speed_report(
        download=_fake_download(downloads, calls),
        upload=_fake_upload(50.0, calls),
    )

    assert report.command == "speed"
    assert report.schema_version == 1
    assert report.duration_ms >= 0
    assert [section.id for section in report.sections] == ["speed"]
    assert report.findings == []
    assert report.errors == []
    assert report.critical_findings() == []

    # 3 个下载源 + 1 个上传源，调用参数带预算内的 max_seconds / timeout
    assert [call[0] for call in calls] == [*_DOWNLOAD_NAMES, _UPLOAD_NAME]
    assert [call[1] for call in calls] == [url for _, url in DOWNLOAD_SOURCES] + [UPLOAD_SOURCE[1]]
    assert all(0 < call[2]["max_seconds"] <= 15.0 for call in calls)
    assert all(0 < call[2]["timeout"] <= 10.0 for call in calls)

    section = _section(report, "speed")
    assert len(section.rows) == 4
    assert _row(section, "阿里云镜像")["速率(Mbps)"] == pytest.approx(300.0)
    assert _row(section, "阿里云镜像")["状态"] == "成功"

    download_metric = _metric(section, "download")
    assert download_metric.value == pytest.approx(300.0)
    assert download_metric.unit == "Mbps"
    assert download_metric.available is True
    # Policy 没有速率档位，不应凭空造阈值
    assert download_metric.good is None
    assert download_metric.warn is None

    upload_metric = _metric(section, "upload")
    assert upload_metric.value == pytest.approx(50.0)
    assert upload_metric.available is True
    assert section.findings == []


# ===========================================================================
# 全失败
# ===========================================================================
def test_speed_all_sources_failing_does_not_crash_and_keeps_reasons() -> None:
    downloads = dict.fromkeys(_DOWNLOAD_NAMES)

    report = build_speed_report(
        download=_fake_download(downloads),
        upload=_fake_upload(None),
    )

    section = _section(report, "speed")
    assert _codes(section) == {SPEED_FAIL}
    assert any(finding.severity is Severity.critical for finding in section.findings)
    critical = [finding for finding in section.findings if finding.severity is Severity.critical]
    assert len(critical) == 1
    assert "全部失败" in critical[0].title

    assert _metric(section, "download").available is False
    assert _metric(section, "upload").available is False
    assert _metric(section, "download").note is not None

    assert len(report.errors) == 4
    assert {error.source for error in report.errors} == {
        *(f"speed:{name}" for name in _DOWNLOAD_NAMES),
        f"speed:{_UPLOAD_NAME}",
    }
    assert all(error.code == ProbeErrorCode.UNAVAILABLE for error in report.errors)
    for name in [*_DOWNLOAD_NAMES, _UPLOAD_NAME]:
        assert _row(section, name)["状态"], "失败源必须保留原因"
    assert _row(section, _UPLOAD_NAME)["状态"] == "上传连接被重置"


# ===========================================================================
# 部分失败
# ===========================================================================
def test_speed_partial_source_failure_keeps_other_results() -> None:
    downloads = {
        "Cloudflare": 100.0,
        "阿里云镜像": RuntimeError("连接被重置"),
        "清华镜像": 200.0,
    }

    report = build_speed_report(
        download=_fake_download(downloads),
        upload=_fake_upload(60.0),
    )

    section = _section(report, "speed")
    assert _codes(section) == {SPEED_FAIL}
    assert section.findings[0].severity is Severity.warn
    assert "阿里云镜像" in section.findings[0].title
    assert _metric(section, "download").value == pytest.approx(200.0)
    assert _metric(section, "download").available is True

    assert [error.source for error in report.errors] == ["speed:阿里云镜像"]
    assert report.errors[0].code == ProbeErrorCode.UNAVAILABLE
    failed = _row(section, "阿里云镜像")
    assert failed["速率(Mbps)"] is None
    assert "连接被重置" in failed["状态"]


def test_speed_partial_connection_failure_keeps_rate_and_reason() -> None:
    partial = SpeedResult(name="Cloudflare", mbps=50.0, bytes=1024, seconds=0.5, error="HTTP 500")

    report = build_speed_report(
        download=_fake_download({"Cloudflare": partial}),
        upload=_fake_upload(40.0),
    )

    section = _section(report, "speed")
    assert _metric(section, "download").value == pytest.approx(100.0)
    assert _codes(section) == {SPEED_FAIL}
    assert "部分失败" in section.findings[0].title
    assert _row(section, "Cloudflare")["速率(Mbps)"] == pytest.approx(50.0)
    assert _row(section, "Cloudflare")["状态"] == "HTTP 500"
    assert [error.source for error in report.errors] == ["speed:Cloudflare"]


def test_speed_upload_failure_does_not_affect_download_metric() -> None:
    report = build_speed_report(
        download=_fake_download({}),
        upload=_fake_upload(None),
    )

    section = _section(report, "speed")
    assert _metric(section, "download").available is True
    assert _metric(section, "upload").available is False
    assert _codes(section) == {SPEED_FAIL}
    assert section.findings[0].severity is Severity.warn
    assert _row(section, _UPLOAD_NAME)["状态"] == "上传连接被重置"


def test_speed_all_downloads_failing_is_critical_even_if_upload_works() -> None:
    report = build_speed_report(
        download=_fake_download(dict.fromkeys(_DOWNLOAD_NAMES)),
        upload=_fake_upload(30.0),
    )

    section = _section(report, "speed")
    assert _metric(section, "upload").available is True
    assert _metric(section, "download").available is False
    critical = [finding for finding in section.findings if finding.severity is Severity.critical]
    assert len(critical) == 1
    assert critical[0].code == SPEED_FAIL
    assert len(report.critical_findings()) == 1


# ===========================================================================
# 预算
# ===========================================================================
def test_speed_budget_exhaustion_skips_probes_without_sleeping() -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("预算已耗尽时不应启动测速")

    report = build_speed_report(download=forbidden, upload=forbidden, budget_seconds=0.0)

    section = _section(report, "speed")
    assert _metric(section, "download").available is False
    assert _metric(section, "upload").available is False
    assert _codes(section) == {SPEED_FAIL}
    assert len(report.errors) == 4
    assert {error.code for error in report.errors} == {ProbeErrorCode.TIMEOUT}
    assert {row["状态"] for row in section.rows} == {"预算已耗尽"}
