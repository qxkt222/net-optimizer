# -*- coding: utf-8 -*-
"""``netopt health`` CLI 测试：JSON 输出与退出码。

``netopt.cli.health_cmd.build_health_report`` 一律 monkeypatch 成固定
:class:`Report`，因此本文件**不探测、不联网、不执行系统命令**。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

import netopt.cli as cli
from netopt.commands import health as health_cmd
from netopt.domain import Finding, ProbeError, Report, Score, Section, Severity

runner = CliRunner()


def _report(*, critical: bool = False, denied: bool = False) -> Report:
    """固定健康报告；``critical`` / ``denied`` 控制退出码。"""
    findings: list[Finding] = []
    if critical:
        findings.append(
            Finding(
                code="GATEWAY_UNREACHABLE",
                severity=Severity.critical,
                title="网关不可达",
                detail="测试用固定结论",
            )
        )
    errors: list[ProbeError] = []
    if denied:
        errors.append(
            ProbeError(
                code="denied",
                source="health",
                message="需要管理员权限",
                retryable=False,
            )
        )
    return Report(
        command="health",
        started_at=datetime.now(UTC),
        duration_ms=1,
        environment={"admin": False, "history": "C:/tmp/history.jsonl"},
        sections=[
            Section(
                id="health",
                title="健康评分",
                metrics=[],
                rows=[{"项目": "网关", "得分": "0/15"}],
                findings=findings,
            )
        ],
        findings=[],
        errors=errors,
        score=Score(total=90, grade="优", items=[]),
    )


def _patch(
    monkeypatch: pytest.MonkeyPatch, *, critical: bool = False, denied: bool = False
) -> Report:
    report = _report(critical=critical, denied=denied)
    monkeypatch.setattr(health_cmd, "build_health_report", lambda: report)
    return report


# ===========================================================================
# JSON 输出
# ===========================================================================
def test_health_local_json_stdout_is_only_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch)

    result = runner.invoke(cli.app, ["health", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)  # 整段 stdout 可解析 → 没有夹带提示行
    assert payload["command"] == "health"
    assert payload["score"]["total"] == 90
    assert payload["score"]["grade"] == "优"
    assert payload["sections"][0]["id"] == "health"
    assert result.stdout.startswith("{")


def test_health_global_json_option_also_applies(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch)

    result = runner.invoke(cli.app, ["--json", "health"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "health"
    assert payload["score"]["total"] == 90


# ===========================================================================
# 退出码
# ===========================================================================
def test_health_critical_finding_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, critical=True)

    result = runner.invoke(cli.app, ["health", "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["sections"][0]["findings"][0]["severity"] == "critical"


def test_health_permission_error_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, denied=True)

    result = runner.invoke(cli.app, ["health", "--json"])

    assert result.exit_code == 3


# ===========================================================================
# 文本路径与异常边界
# ===========================================================================
def test_health_text_path_uses_render_report(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _patch(monkeypatch)
    rendered: list[Report] = []
    monkeypatch.setattr(cli, "_render_text", lambda value: rendered.append(value))

    result = runner.invoke(cli.app, ["health"])

    assert result.exit_code == 0
    assert rendered == [report]


def test_health_internal_error_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> Report:
        raise RuntimeError("炸了")

    monkeypatch.setattr(health_cmd, "build_health_report", boom)

    result = runner.invoke(cli.app, ["health", "--json"])

    assert result.exit_code == 4
    assert "内部错误" in result.stderr
    assert result.stdout == "", "内部错误不得污染 stdout"
