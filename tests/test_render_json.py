# -*- coding: utf-8 -*-
"""JSON 渲染测试：可解析、schema_version、中文不转义、字段完整。"""

from __future__ import annotations

import json as jsonlib
from datetime import UTC, datetime

import pytest

from netopt.domain.report import (
    Finding,
    Metric,
    ProbeError,
    Report,
    Section,
    Severity,
)
from netopt.render.json import render_json


def _report() -> Report:
    """含中文、缺失指标与探测错误的报告。"""
    return Report(
        command="status",
        started_at=datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC),
        duration_ms=1234,
        environment={"admin": False, "locale": "zh-CN", "hostname": "网关主机"},
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
                        note="探测超时",
                    ),
                ],
                rows=[{"ip": "192.0.2.1"}],
                findings=[
                    Finding(
                        code="GATEWAY_LATENCY_HIGH",
                        severity=Severity.warn,
                        title="网关延迟偏高",
                        detail="平均 35 ms",
                    )
                ],
            )
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


def test_json_is_parseable_and_schema_version() -> None:
    """输出必须是合法 JSON，且带 schema_version=1。"""
    parsed = jsonlib.loads(render_json(_report()))
    assert parsed["schema_version"] == 1


def test_json_keeps_chinese_unescaped() -> None:
    """中文按 UTF-8 原样输出，不做 ``\\uXXXX`` 转义。"""
    out = render_json(_report())
    assert "网关" in out
    assert "网关探测超时" in out


def test_json_indent_none_is_single_line() -> None:
    """indent=None 时输出单行紧凑 JSON。"""
    out = render_json(_report(), indent=None)
    assert "\n" not in out
    assert jsonlib.loads(out)["schema_version"] == 1


def test_json_fields_are_complete() -> None:
    """Section / Metric / ProbeError 的字段一个都不能少。"""
    parsed = jsonlib.loads(render_json(_report()))
    section = parsed["sections"][0]
    assert set(section) == {"id", "title", "metrics", "rows", "findings"}
    metric = section["metrics"][0]
    assert set(metric) == {
        "key",
        "label",
        "value",
        "unit",
        "good",
        "warn",
        "available",
        "note",
    }
    missing = section["metrics"][1]
    assert missing["value"] is None
    assert missing["available"] is False
    error = parsed["errors"][0]
    assert set(error) == {"code", "source", "message", "retryable"}
    assert error["retryable"] is True
    assert section["findings"][0]["severity"] == "warn"


def test_render_json_does_not_print(capsys: pytest.CaptureFixture[str]) -> None:
    """render_json 只返回字符串，不写 stdout。"""
    render_json(_report())
    assert capsys.readouterr().out == ""
