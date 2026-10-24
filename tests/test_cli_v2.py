# -*- coding: utf-8 -*-
"""v2 CLI（``netopt.cli``）测试：全局选项、JSON 输出与退出码矩阵。

报告构造函数被 monkeypatch 成固定 :class:`Report`，因此本文件
**不探测、不联网、不执行系统命令**。
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

import netopt.cli as cli
from netopt.commands import status as status_cmd
from netopt.domain import Finding, ProbeError, Report, Section, Severity

runner = CliRunner()


def _report(*, critical: bool = False, denied: bool = False) -> Report:
    """固定报告：默认无结论；``critical`` / ``denied`` 控制退出码。"""
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
                source="test",
                message="需要管理员权限",
                retryable=False,
            )
        )
    return Report(
        command="status",
        started_at=datetime.now(UTC),
        duration_ms=3,
        environment={"admin": False},
        sections=[
            Section(
                id="gateway",
                title="网关",
                metrics=[],
                rows=[],
                findings=findings,
            )
        ],
        findings=[],
        errors=errors,
    )


@pytest.fixture
def fixed_report(monkeypatch):
    report = _report()
    monkeypatch.setattr(status_cmd, "build_status_report", lambda: report)
    return report


def test_status_json_stdout_is_only_json(fixed_report) -> None:
    result = runner.invoke(cli.app, ["--json", "status"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)  # 整段 stdout 可解析 → 没有夹带提示行
    assert payload["command"] == "status"
    assert payload["sections"][0]["id"] == "gateway"
    assert payload["errors"] == []


def test_status_critical_finding_exits_2(monkeypatch) -> None:
    monkeypatch.setattr(status_cmd, "build_status_report", lambda: _report(critical=True))

    result = runner.invoke(cli.app, ["--json", "status"])

    assert result.exit_code == 2


def test_status_permission_error_exits_3(monkeypatch) -> None:
    monkeypatch.setattr(status_cmd, "build_status_report", lambda: _report(denied=True))

    result = runner.invoke(cli.app, ["--json", "status"])

    assert result.exit_code == 3


def test_status_text_path_uses_render_report(fixed_report, monkeypatch) -> None:
    rendered: list[Report] = []
    monkeypatch.setattr(cli, "_render_text", lambda report: rendered.append(report))

    result = runner.invoke(cli.app, ["status"])

    assert result.exit_code == 0
    assert rendered == [fixed_report]


def test_status_internal_error_exits_4(monkeypatch) -> None:
    def boom() -> Report:
        raise RuntimeError("炸了")

    monkeypatch.setattr(status_cmd, "build_status_report", boom)

    result = runner.invoke(cli.app, ["--json", "status"])

    assert result.exit_code == 4
    assert "内部错误" in result.stderr
    assert result.stdout == "", "内部错误不得污染 stdout"


def test_version_command_prints_version() -> None:
    result = runner.invoke(cli.app, ["version"])

    assert result.exit_code == 0
    assert "net-optimizer" in result.stdout


def test_no_color_sets_env(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(status_cmd, "build_status_report", lambda: _report())
    monkeypatch.setattr(cli, "_render_text", lambda report: None)

    result = runner.invoke(cli.app, ["--no-color", "status"])

    assert result.exit_code == 0
    assert os.environ.get("NO_COLOR") == "1"


def test_main_returns_exit_code_without_sys_exit(fixed_report) -> None:
    """兼容壳按返回值取退出码，``main`` 不能自己 sys.exit。"""
    assert cli.main(["status"]) == 0


def test_main_usage_error_returns_1() -> None:
    assert cli.main(["no-such-command"]) == 1
