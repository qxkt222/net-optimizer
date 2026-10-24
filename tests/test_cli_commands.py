# -*- coding: utf-8 -*-
"""v2 CLI 子命令接线测试：ping / dns / http / speed / trace / wifi / full。

所有命令层 builder 一律 monkeypatch 成固定 :class:`Report`，因此本文件
**不探测、不联网、不执行系统命令**。覆盖：

- 命令名与报告原样透传（``command`` 字段、JSON 可解析）；
- ``ping`` / ``trace`` 的 ``TARGET`` 位置参数透传（缺省为 ``None``）；
- 全局 ``--json`` 与命令级 ``--json`` 等价，stdout 只有 JSON；
- 退出码矩阵：0（正常）/ 2（critical）/ 3（权限）/ 4（内部错误）；
- ``full`` 的合成口径：sections / findings / errors / duration_ms / score。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from typer.testing import CliRunner

import netopt.cli as cli
from netopt.commands import dns as dns_cmd
from netopt.commands import full as full_cmd
from netopt.commands import http as http_cmd
from netopt.commands import ping as ping_cmd
from netopt.commands import speed as speed_cmd
from netopt.commands import trace as trace_cmd
from netopt.commands import wifi as wifi_cmd
from netopt.domain import Finding, ProbeError, Report, Score, Section, Severity

runner = CliRunner()

#: (命令名, 命令模块, builder 属性)。模块对象用于 monkeypatch，无需真实探测。
COMMANDS: list[tuple[str, Any, str]] = [
    ("ping", ping_cmd, "build_ping_report"),
    ("dns", dns_cmd, "build_dns_report"),
    ("http", http_cmd, "build_http_report"),
    ("speed", speed_cmd, "build_speed_report"),
    ("trace", trace_cmd, "build_trace_report"),
    ("wifi", wifi_cmd, "build_wifi_report"),
    ("full", full_cmd, "build_full_report"),
]

COMMAND_IDS = [name for name, _, _ in COMMANDS]


def _report(
    command: str,
    *,
    critical: bool = False,
    denied: bool = False,
    section_id: str | None = None,
    duration_ms: int = 5,
    score: Score | None = None,
) -> Report:
    """造一份固定报告；``critical`` / ``denied`` 控制退出码。"""
    findings: list[Finding] = []
    if critical:
        findings.append(
            Finding(
                code="TEST_CRITICAL",
                severity=Severity.critical,
                title="测试故障",
                detail="用于验证 critical 退出码",
            )
        )
    errors: list[ProbeError] = []
    if denied:
        errors.append(
            ProbeError(
                code="denied",
                source=command,
                message="需要管理员权限",
                retryable=False,
            )
        )
    return Report(
        command=command,
        started_at=datetime.now(UTC),
        duration_ms=duration_ms,
        environment={"admin": False, "component": command},
        sections=[Section(id=section_id or command, title=command, findings=findings)],
        findings=[],
        errors=errors,
        score=score,
    )


def _patch(monkeypatch: pytest.MonkeyPatch, module: Any, attr: str, report: Report) -> None:
    """把命令层的 builder 换成固定返回值（接受任意参数，兼容 target / run / api）。"""
    monkeypatch.setattr(module, attr, lambda *args, **kwargs: report)


# ===========================================================================
# JSON 输出
# ===========================================================================
@pytest.mark.parametrize(("name", "module", "attr"), COMMANDS, ids=COMMAND_IDS)
def test_command_local_json_stdout_is_only_json(
    monkeypatch: pytest.MonkeyPatch, name: str, module: Any, attr: str
) -> None:
    _patch(monkeypatch, module, attr, _report(name))

    result = runner.invoke(cli.app, [name, "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)  # 整段 stdout 可解析 → 没有夹带提示行
    assert payload["command"] == name
    assert result.stdout.startswith("{")


@pytest.mark.parametrize(("name", "module", "attr"), COMMANDS, ids=COMMAND_IDS)
def test_command_global_json_option_also_applies(
    monkeypatch: pytest.MonkeyPatch, name: str, module: Any, attr: str
) -> None:
    _patch(monkeypatch, module, attr, _report(name))

    result = runner.invoke(cli.app, ["--json", name])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["command"] == name


@pytest.mark.parametrize(("name", "module", "attr"), COMMANDS, ids=COMMAND_IDS)
def test_command_text_path_uses_render_report(
    monkeypatch: pytest.MonkeyPatch, name: str, module: Any, attr: str
) -> None:
    report = _report(name)
    _patch(monkeypatch, module, attr, report)
    rendered: list[Report] = []
    monkeypatch.setattr(cli, "_render_text", lambda value: rendered.append(value))

    result = runner.invoke(cli.app, [name])

    assert result.exit_code == 0
    assert rendered == [report]


# ===========================================================================
# TARGET 透传
# ===========================================================================
@pytest.mark.parametrize(
    ("name", "module", "attr"),
    [("ping", ping_cmd, "build_ping_report"), ("trace", trace_cmd, "build_trace_report")],
)
def test_target_argument_is_forwarded(
    monkeypatch: pytest.MonkeyPatch, name: str, module: Any, attr: str
) -> None:
    calls: list[Any] = []

    def builder(target: str | None = None, **kwargs: Any) -> Report:
        calls.append(target)
        return _report(name)

    monkeypatch.setattr(module, attr, builder)

    assert runner.invoke(cli.app, [name, "1.1.1.1", "--json"]).exit_code == 0
    assert runner.invoke(cli.app, [name, "--json"]).exit_code == 0
    assert calls == ["1.1.1.1", None], "显式目标要透传，缺省目标保持 None（由命令层取默认值）"


# ===========================================================================
# 退出码矩阵
# ===========================================================================
@pytest.mark.parametrize(("name", "module", "attr"), COMMANDS, ids=COMMAND_IDS)
def test_critical_finding_exits_2(
    monkeypatch: pytest.MonkeyPatch, name: str, module: Any, attr: str
) -> None:
    _patch(monkeypatch, module, attr, _report(name, critical=True))

    result = runner.invoke(cli.app, [name, "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["sections"][0]["findings"][0]["severity"] == "critical"


@pytest.mark.parametrize(("name", "module", "attr"), COMMANDS, ids=COMMAND_IDS)
def test_permission_error_exits_3(
    monkeypatch: pytest.MonkeyPatch, name: str, module: Any, attr: str
) -> None:
    _patch(monkeypatch, module, attr, _report(name, denied=True))

    result = runner.invoke(cli.app, [name, "--json"])

    assert result.exit_code == 3


def test_builder_exception_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Report:
        raise RuntimeError("炸了")

    monkeypatch.setattr(ping_cmd, "build_ping_report", boom)

    result = runner.invoke(cli.app, ["ping", "--json"])

    assert result.exit_code == 4
    assert "内部错误" in result.stderr
    assert result.stdout == "", "内部错误不得污染 stdout"


# ===========================================================================
# full 的合成口径
# ===========================================================================
def test_full_report_combines_components() -> None:
    score = Score(total=88, grade="良", items=[])
    status = _report("status", section_id="gateway", duration_ms=10, score=score)
    speed = _report("speed", duration_ms=20)
    trace = _report("trace", duration_ms=30, critical=True)
    wifi = _report("wifi", duration_ms=40, denied=True)
    top_finding = Finding(
        code="TEST_FULL",
        severity=Severity.info,
        title="合成结论",
        detail="顶层 findings 应被拼接",
    )
    speed = speed.model_copy(update={"findings": [top_finding]})

    # 零参 builder：全默认参数时不应被塞入 run=None / api=None。
    report = full_cmd.build_full_report(
        status_builder=lambda: status,
        speed_builder=lambda: speed,
        trace_builder=lambda: trace,
        wifi_builder=lambda: wifi,
    )

    assert report.command == "full"
    assert report.duration_ms == 100, "duration_ms 必须是四份子报告之和"
    assert [section.id for section in report.sections] == ["gateway", "speed", "trace", "wifi"]
    assert report.findings == [top_finding], "顶层 findings 依次拼接"
    assert [error.source for error in report.errors] == ["wifi"], "errors 依次拼接"
    assert report.score is score, "score 沿用 status 的分数"
    assert report.environment == status.environment


def test_full_report_resolves_default_builders_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """默认 builder 必须在调用时解析，monkeypatch 模块属性才能生效。"""
    reports = {
        "status": _report("status", section_id="gateway"),
        "speed": _report("speed"),
        "trace": _report("trace"),
        "wifi": _report("wifi"),
    }
    monkeypatch.setattr(full_cmd, "build_status_report", lambda **kw: reports["status"])
    monkeypatch.setattr(full_cmd, "build_speed_report", lambda **kw: reports["speed"])
    monkeypatch.setattr(full_cmd, "build_trace_report", lambda **kw: reports["trace"])
    monkeypatch.setattr(full_cmd, "build_wifi_report", lambda **kw: reports["wifi"])

    report = full_cmd.build_full_report()

    assert [section.id for section in report.sections] == ["gateway", "speed", "trace", "wifi"]


def test_full_report_forwards_run_and_api() -> None:
    """run 只透传给 status / trace，api 只透传给 status / wifi（各 builder 签名不同）。"""
    seen: dict[str, dict[str, Any]] = {}

    def recorder(name: str) -> Any:
        def _builder(**kwargs: Any) -> Report:
            seen[name] = kwargs
            return _report(name)

        return _builder

    run_token = object()
    api_token = object()
    full_cmd.build_full_report(
        run=run_token,  # type: ignore[arg-type]
        api=api_token,  # type: ignore[arg-type]
        status_builder=recorder("status"),
        speed_builder=recorder("speed"),
        trace_builder=recorder("trace"),
        wifi_builder=recorder("wifi"),
    )

    assert seen["status"] == {"run": run_token, "api": api_token}
    assert seen["speed"] == {}
    assert seen["trace"] == {"run": run_token}
    assert seen["wifi"] == {"api": api_token}
