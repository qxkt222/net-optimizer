# -*- coding: utf-8 -*-
"""text 渲染测试：信息完整、纯文本无 ANSI、空报告不崩。"""

from __future__ import annotations

import io
from datetime import UTC, datetime

from rich.console import Console

from netopt.domain.report import (
    Evidence,
    Finding,
    Metric,
    ProbeError,
    Report,
    Section,
    Severity,
)
from netopt.render.text import format_value, render_plain, render_report


def _report() -> Report:
    """两节、四种 severity、一条探测错误的完整报告。"""
    return Report(
        command="status",
        started_at=datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC),
        duration_ms=1234,
        environment={"admin": False, "locale": "zh-CN"},
        sections=[
            Section(
                id="gateway",
                title="网关",
                metrics=[
                    Metric(
                        key="gateway_latency",
                        label="网关延迟",
                        value=3.5,
                        unit="ms",
                        good=5,
                        warn=30,
                    ),
                    Metric(
                        key="gateway_loss",
                        label="网关丢包",
                        value=None,
                        unit="%",
                        good=2,
                        warn=50,
                        available=False,
                    ),
                ],
                rows=[{"ip": "192.0.2.1", "metric": 20, "custom_key": "自定义值"}],
                findings=[
                    Finding(
                        code="GATEWAY_LATENCY_HIGH",
                        severity=Severity.warn,
                        title="网关延迟偏高",
                        detail="平均 35 ms",
                        advice=["检查网关负载"],
                        evidence=[
                            Evidence(source="ping", detail="4/4 回复", raw_ref="raw/run-1/ping.txt")
                        ],
                    )
                ],
            ),
            Section(
                id="dns",
                title="DNS",
                metrics=[
                    Metric(
                        key="dns_latency",
                        label="DNS 解析延迟",
                        value=45.0,
                        unit="ms",
                        good=30,
                        warn=100,
                    ),
                    Metric(
                        key="http_ttfb",
                        label="HTTP 首字节",
                        value=900.0,
                        unit="ms",
                        good=150,
                        warn=500,
                    ),
                ],
                rows=[{"target": "223.5.5.5", "servers": ["223.5.5.5", "119.29.29.29"]}],
                findings=[
                    Finding(
                        code="DNS_OK",
                        severity=Severity.ok,
                        title="DNS 响应正常",
                        detail="解析成功",
                    ),
                    Finding(
                        code="DNS_SLOW",
                        severity=Severity.info,
                        title="DNS 解析偏慢",
                        detail="可换用更快的解析服务",
                    ),
                    Finding(
                        code="DNS_FAIL",
                        severity=Severity.critical,
                        title="DNS 解析失败",
                        detail="所有解析服务均超时",
                    ),
                ],
            ),
        ],
        findings=[],
        errors=[
            ProbeError(
                code="timeout",
                source="ping",
                message="网关探测超时",
                retryable=True,
            )
        ],
    )


def test_render_plain_contains_all_content() -> None:
    """纯文本必须带上环境摘要、指标、结论与探测错误。"""
    out = render_plain(_report())
    for expected in (
        "status",
        "1234 ms",
        "管理员: 否",
        "网关延迟",
        "3.5 ms",
        "不可用",
        "DNS 解析延迟",
        "DNS 解析失败",
        "DNS 解析偏慢",
        "DNS 响应正常",
        "网关延迟偏高",
        "网关探测超时",
        "timeout",
        "ping",
        "raw/run-1/ping.txt",
        "地址：192.0.2.1",
        "跃点数：20",
        "目标：223.5.5.5",
        "服务器：223.5.5.5, 119.29.29.29",
        "自定义值",
    ):
        assert expected in out, expected
    # good/warn 分档结果：3.5<=5 -> ok，45<=100 -> warn，900>500 -> bad。
    for status in ("ok", "warn", "bad"):
        assert status in out, status


def test_format_value_precision() -> None:
    """按单位选精度：ms/% 一位、Mbps 两位、整数型单位不留小数、缺失用 -。"""
    assert format_value(24.2083, "ms") == "24.2 ms"
    assert format_value(2.0, "%") == "2.0 %"
    assert format_value(24.2083, "Mbps") == "24.21 Mbps"
    assert format_value(1.0, "") == "1"
    assert format_value(3.0, "个") == "3 个"
    assert format_value(None, "ms") == "-"
    assert format_value(-42.55, "dBm") == "-42.55 dBm"


def test_rows_use_chinese_labels_and_keep_unknown_keys() -> None:
    """已知键映射中文标签，未知键原样显示，且不再出现 key/value 表头。"""
    out = render_plain(_report())
    assert "地址：192.0.2.1" in out
    assert "跃点数：20" in out
    assert "目标：223.5.5.5" in out
    assert "服务器：223.5.5.5, 119.29.29.29" in out
    assert "custom_key：自定义值" in out
    assert "metric：" not in out


def test_render_plain_has_no_ansi() -> None:
    """供 GUI / 日志消费的文本不能含 ANSI 转义序列。"""
    out = render_plain(_report())
    assert "\x1b[" not in out


def test_render_report_writes_to_console() -> None:
    """render_report 写入调用方提供的 Console，且不自行 print 到 stdout。"""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False)
    render_report(_report(), console=console)
    written = buffer.getvalue()
    assert "网关延迟" in written
    assert "网关探测超时" in written


def test_empty_report_is_safe() -> None:
    """空 sections / findings / errors 不应抛异常。"""
    empty = Report(
        command="status",
        started_at=datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC),
        duration_ms=0,
        environment={},
        sections=[],
        findings=[],
        errors=[],
    )
    out = render_plain(empty)
    assert "没有可展示的小节" in out
    assert "管理员: 未知" in out
    buffer = io.StringIO()
    render_report(empty, console=Console(file=buffer, force_terminal=False))
    assert "没有可展示的小节" in buffer.getvalue()
