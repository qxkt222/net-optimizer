# -*- coding: utf-8 -*-
"""Report 契约测试：序列化往返、冻结、默认值与缺失值语义。"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from netopt.domain.report import (
    SCORE_ITEM_KEYS,
    Evidence,
    Finding,
    Metric,
    ProbeError,
    Report,
    Score,
    Section,
    Severity,
)


def _full_report() -> Report:
    """构造一份覆盖所有字段的报告，用作往返与冻结测试的基准。"""
    finding = Finding(
        code="WAN_LATENCY_HIGH",
        severity=Severity.warn,
        title="外网延迟偏高",
        detail="平均 120 ms",
        advice=["重启光猫"],
        evidence=[Evidence(source="ping", detail="4/4 回复", raw_ref="raw/run-1/ping.txt")],
    )
    return Report(
        command="status",
        started_at=datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC),
        duration_ms=1234,
        environment={"os_build": "22631", "admin": False, "locale": "zh-CN"},
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
                    )
                ],
                rows=[{"ip": "192.0.2.1"}],
                findings=[finding],
            )
        ],
        findings=[finding],
        errors=[ProbeError(code="timeout", source="ping", message="超时", retryable=True)],
        score=Score(total=88, grade="B", items=[{"key": "wan", "weight": 25, "earned": 20}]),
    )


def test_json_roundtrip_equal() -> None:
    original = _full_report()
    restored = Report.model_validate_json(original.model_dump_json())
    assert restored == original


def test_datetime_serialized_as_iso8601() -> None:
    payload = _full_report().model_dump_json()
    assert '"started_at":"2026-10-24T12:00:00' in payload


def test_unknown_fields_are_ignored() -> None:
    data = _full_report().model_dump()
    data["future_field"] = {"anything": 1}
    data["sections"][0]["future_section_field"] = "x"
    data["sections"][0]["metrics"][0]["future_metric_field"] = 42

    restored = Report.model_validate(data)

    assert "future_field" not in restored.model_dump()
    assert "future_section_field" not in restored.sections[0].model_dump()
    assert "future_metric_field" not in restored.sections[0].metrics[0].model_dump()


def test_frozen_report_rejects_assignment() -> None:
    report = _full_report()
    with pytest.raises(ValidationError):
        report.command = "other"  # type: ignore[misc]


def test_frozen_nested_models_reject_assignment() -> None:
    metric = Metric(key="k", label="L", value=1.0)
    with pytest.raises(ValidationError):
        metric.value = 2.0  # type: ignore[misc]


def test_schema_version_defaults_to_one() -> None:
    report = Report(
        command="status",
        started_at=datetime(2026, 10, 24, tzinfo=UTC),
        duration_ms=0,
        environment={},
        sections=[],
        findings=[],
        errors=[],
    )
    assert report.schema_version == 1
    assert report.score is None


def test_default_lists_are_not_shared_between_instances() -> None:
    first = Section(id="a", title="A")
    second = Section(id="b", title="B")
    first.metrics.append(Metric(key="k", label="L", value=1.0))
    first.rows.append({"x": 1})
    first.findings.append(Finding(code="X", severity=Severity.ok, title="t", detail="d"))

    assert second.metrics == []
    assert second.rows == []
    assert second.findings == []

    finding_a = Finding(code="X", severity=Severity.ok, title="t", detail="d")
    finding_b = Finding(code="Y", severity=Severity.ok, title="t", detail="d")
    finding_a.advice.append("a")
    finding_a.evidence.append(Evidence(source="s"))
    assert finding_b.advice == []
    assert finding_b.evidence == []


def test_missing_value_is_serializable() -> None:
    metric = Metric(key="mtu", label="MTU", value=None, available=False, note="权限不足")
    payload = metric.model_dump_json()
    assert '"value":null' in payload
    assert '"available":false' in payload
    assert Metric.model_validate_json(payload) == metric


def test_add_section_returns_new_instance() -> None:
    report = _full_report()
    section = Section(id="dns", title="DNS")
    updated = report.add_section(section)

    assert updated is not report
    assert len(report.sections) == 1
    assert len(updated.sections) == 2
    assert updated.sections[-1] == section
    assert updated.command == report.command


def test_score_items_keep_analysis_shape() -> None:
    """items 的键必须与 analysis 产出（v1 ItemScore）一致，序列化后原样保留。"""
    items = [
        {"label": "网关", "score": 15, "weight": 15, "detail": "3 ms / 丢包 0%"},
        {"label": "MTU", "score": 8, "weight": 10, "detail": "1492（PPPoE）"},
    ]
    score = Score(total=92, grade="A", items=items)

    restored = Score.model_validate_json(score.model_dump_json())

    assert SCORE_ITEM_KEYS == ("label", "score", "weight", "detail")
    assert restored == score
    for item in restored.items:
        assert tuple(item) == SCORE_ITEM_KEYS
        assert isinstance(item["score"], int)


def test_to_json_indent() -> None:
    report = _full_report()
    assert "\n" in report.to_json(indent=2)
    assert "\n" not in report.to_json()


def test_critical_findings_collects_top_level_and_sections() -> None:
    critical = Finding(
        code="WAN_UNREACHABLE", severity=Severity.critical, title="不可达", detail="d"
    )
    warning = Finding(code="DNS_SLOW", severity=Severity.warn, title="慢", detail="d")
    report = _full_report().model_copy(
        update={
            "findings": [critical, warning],
            "sections": [
                Section(id="wan", title="外网", findings=[critical]),
                Section(id="dns", title="DNS", findings=[warning]),
            ],
        }
    )

    result = report.critical_findings()

    assert result == [critical, critical]
    assert all(item.severity is Severity.critical for item in result)
