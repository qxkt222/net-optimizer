# -*- coding: utf-8 -*-
"""``netopt.commands.health`` 测试：Report → 评分输入还原 + 历史落盘。

``build_status_report`` 一律 monkeypatch 成构造好的固定 :class:`Report`，
因此本文件**不探测、不联网、不执行任何系统命令**。

评分的预期值按 ``analysis/health.py`` 的规则手算（算式写在注释里），
不拿被测函数的输出反推预期。
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from netopt import history
from netopt.commands import health as health_cmd
from netopt.domain import Finding, FindingCode, Metric, Report, Section, Severity

_WAN_HOST = "www.baidu.com"


def _metric(
    key: str,
    value: float | None,
    *,
    unit: str = "ms",
    available: bool | None = None,
) -> Metric:
    """构造一个 status 风格的指标；``value=None`` 默认不可用。"""
    return Metric(
        key=key,
        label=key,
        value=value,
        unit=unit,
        available=value is not None if available is None else available,
    )


def _status_report(
    *,
    gateway_avg: float | None = 3.0,
    gateway_loss: float | None = 0.0,
    gateway_findings: list[Finding] | None = None,
    dns_avg: float | None = 20.0,
    dns_servers: str | None = "223.5.5.5, 114.114.114.114",
    dns_findings: list[Finding] | None = None,
    http_ttfb: float | None = 100.0,
    mtu_value: float | None = 1500.0,
    mtu_findings: list[Finding] | None = None,
) -> Report:
    """构造五节齐全的 status Report（字段形状与 ``commands.status`` 一致）。"""
    gateway = Section(
        id="gateway",
        title="网关",
        metrics=[
            _metric("latency", gateway_avg),
            _metric("loss", gateway_loss, unit="%", available=gateway_loss is not None),
        ],
        rows=[{"ip": "192.0.2.1", "metric": 25}],
        findings=list(gateway_findings or []),
    )
    wan = Section(
        id="wan",
        title="外网",
        metrics=[_metric("latency", 20.0), _metric("loss", 0.0, unit="%")],
        rows=[{"target": _WAN_HOST}],
    )
    dns = Section(
        id="dns",
        title="DNS",
        metrics=[_metric("latency", dns_avg)],
        rows=[{"servers": dns_servers}] if dns_servers else [],
        findings=list(dns_findings or []),
    )
    http = Section(
        id="http",
        title="HTTP",
        metrics=[_metric("ttfb", http_ttfb)],
        rows=[{"target": _WAN_HOST}],
    )
    mtu = Section(
        id="mtu",
        title="MTU",
        metrics=[_metric("mtu", mtu_value, unit="B")],
        findings=list(mtu_findings or []),
    )
    return Report(
        command="status",
        started_at=datetime.now(UTC),
        duration_ms=5,
        environment={"admin": False},
        sections=[gateway, wan, dns, http, mtu],
        findings=[],
        errors=[],
    )


def _patch_status(monkeypatch: pytest.MonkeyPatch, report: Report) -> dict[str, object]:
    """把 ``commands.health.build_status_report`` 换成固定报告并记录入参。"""
    seen: dict[str, object] = {}

    def _build(**kwargs: object) -> Report:
        seen.update(kwargs)
        return report

    monkeypatch.setattr(health_cmd, "build_status_report", _build)
    return seen


def _codes(findings: list[Finding]) -> set[str]:
    return {finding.code for finding in findings}


# ===========================================================================
# 正常场景
# ===========================================================================
def test_health_normal_scores_high_without_critical(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_status(monkeypatch, _status_report())

    report = health_cmd.build_health_report(history_path=tmp_path / "history.jsonl")

    assert report.command == "health"
    assert report.schema_version == 1
    assert [section.id for section in report.sections] == [
        "gateway",
        "wan",
        "dns",
        "http",
        "mtu",
        "health",
    ]
    assert report.critical_findings() == []
    assert report.findings == []

    assert report.score is not None
    # 手算（默认 Policy）：得分和 = 权重和 = 15+25+20+20+10 = 90 → 归一化 100
    assert report.score.total == 100
    assert report.score.grade == "优"
    assert [item["label"] for item in report.score.items] == ["网关", "外网", "DNS", "HTTP", "MTU"]
    assert report.score.items[0]["score"] == 15

    health_section = report.sections[-1]
    assert health_section.title == "健康评分"
    assert len(health_section.rows) == len(report.score.items)
    assert health_section.rows[0]["得分"] == "15/15"


def test_health_reports_are_built_from_status_metrics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """metric → PingStat / MtuResult 的还原：分数随输入 metric 变化。"""
    _patch_status(
        monkeypatch,
        _status_report(
            gateway_avg=4.0,
            gateway_loss=0.0,
            dns_avg=25.0,
            http_ttfb=140.0,
            mtu_value=1492.0,
        ),
    )

    report = health_cmd.build_health_report(history_path=tmp_path / "history.jsonl")

    assert report.score is not None
    # 手算：得分和 = 15+25+20+20+8（PPPoE 档）= 88，权重和 90 → round(97.78) = 98
    assert report.score.total == 98
    assert report.score.items[4]["score"] == 8
    assert FindingCode.MTU_PPPOE in _codes(report.findings)


# ===========================================================================
# 网关不可达
# ===========================================================================
def test_health_gateway_unreachable_is_critical_and_lowers_score(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    status_finding = Finding(
        code=FindingCode.GATEWAY_UNREACHABLE,
        severity=Severity.critical,
        title="网关不可达",
        detail="status 的固定结论",
    )
    _patch_status(
        monkeypatch,
        _status_report(
            gateway_avg=None,
            gateway_loss=100.0,
            gateway_findings=[status_finding],
        ),
    )

    report = health_cmd.build_health_report(history_path=tmp_path / "history.jsonl")

    assert report.score is not None
    # 手算：得分和 = 0+25+20+20+10 = 75，权重和 90 → round(83.33) = 83
    assert report.score.total == 83
    assert report.score.total < 100, "网关不可达必须拉低总分"
    assert report.score.items[0]["score"] == 0

    criticals = report.critical_findings()
    assert criticals, "网关不可达必须产出 critical"
    gateway = next(f for f in criticals if f.code == FindingCode.GATEWAY_UNREACHABLE)
    assert gateway.severity is Severity.critical
    # target 从 status 网关节的 rows 还原，结论文案中应出现真实网关地址
    assert "192.0.2.1" in gateway.detail


def test_health_mtu_unverified_flag_is_restored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    unverified = Finding(
        code=FindingCode.MTU_UNVERIFIED,
        severity=Severity.info,
        title="MTU 未经确认",
        detail="status 的固定结论",
    )
    _patch_status(
        monkeypatch,
        _status_report(mtu_value=1492.0, mtu_findings=[unverified]),
    )

    report = health_cmd.build_health_report(history_path=tmp_path / "history.jsonl")

    assert FindingCode.MTU_UNVERIFIED in _codes(report.findings)
    assert report.critical_findings() == []


# ===========================================================================
# 历史记录
# ===========================================================================
def test_health_appends_history_record(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_status(monkeypatch, _status_report())
    path = tmp_path / "state" / "history.jsonl"

    report = health_cmd.build_health_report(history_path=path)

    score = report.score
    assert score is not None
    records = history.load(path)
    assert len(records) == 1
    record = records[0]
    assert record["kind"] == "health"
    assert record["schema_version"] == 1
    assert record["score"] == score.total
    assert record["grade"] == score.grade
    assert record["items"] == score.items
    assert datetime.fromisoformat(record["ts"]).tzinfo is not None
    assert report.environment["history"] == str(path)


def test_health_default_history_path_uses_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_status(monkeypatch, _status_report())
    default = tmp_path / "default-history.jsonl"
    monkeypatch.setattr(health_cmd.paths, "history_path", lambda: default)

    report = health_cmd.build_health_report()

    assert report.environment["history"] == str(default)
    assert len(history.load(default)) == 1


def test_health_history_write_failure_warns_without_crashing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_status(monkeypatch, _status_report())
    # 把历史路径指向一个已存在的目录：open(..., "a") 必然失败。
    bad_path = tmp_path / "history-is-a-directory"
    bad_path.mkdir()

    report = health_cmd.build_health_report(history_path=bad_path)

    assert report.score is not None
    assert report.score.total == 100, "历史写失败不得影响评分"
    finding = next(item for item in report.findings if item.code == FindingCode.SYSTEM_UNAVAILABLE)
    assert finding.severity is Severity.warn
    assert str(bad_path) in finding.detail
    assert report.critical_findings() == []


# ===========================================================================
# DNS 边界：只有 IPv6 服务器时不得误报解析失败
# ===========================================================================
def test_health_ipv6_only_dns_is_not_scored_as_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ipv6_only = Finding(
        code=FindingCode.DNS_IPV6_ONLY,
        severity=Severity.info,
        title="仅使用 IPv6 DNS",
        detail="未做 IPv4 实测，不代表解析失败",
    )
    _patch_status(
        monkeypatch,
        _status_report(
            dns_avg=None,
            dns_servers="fd00:db8::1",
            dns_findings=[ipv6_only],
        ),
    )

    report = health_cmd.build_health_report(history_path=tmp_path / "history.jsonl")

    assert report.score is not None
    # DNS 不参与打分：得分和 = 权重和 = 15+25+20+10 = 70 → 归一化 100
    assert report.score.total == 100
    assert "DNS" not in [item["label"] for item in report.score.items]
    assert FindingCode.DNS_FAIL not in _codes(report.findings)
    assert FindingCode.DNS_NO_CONFIG not in _codes(report.findings)
    assert report.critical_findings() == []
