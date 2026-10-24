# -*- coding: utf-8 -*-
"""``netopt.commands.auto`` 与 ``netopt auto`` 的测试。

两条路径都不真实探测、不修复：

- 命令层用注入的假 health builder / fix applier，断言调用顺序与合成口径；
- CLI 层 monkeypatch ``build_auto_report`` 与权限函数，只验证权限门与渲染。

``tests/conftest.py`` 的 autouse 夹具还会拦截任何真实子进程，双保险。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from typer.testing import CliRunner

import netopt.cli as cli
from netopt.commands import auto as auto_cmd
from netopt.commands import undo as undo_cmd
from netopt.commands.fix import FixKind, FixPlan, FixResult, FixStep
from netopt.domain import Finding, ProbeError, Report, Score, Section, Severity

runner = CliRunner()


def _finding(code: str, severity: Severity = Severity.info) -> Finding:
    """构造一条最小 Finding。"""
    return Finding(code=code, severity=severity, title=code, detail=f"{code} 的说明")


def _health_report(
    total: int,
    *,
    top_findings: list[Finding] | None = None,
    section_findings: list[Finding] | None = None,
    errors: list[ProbeError] | None = None,
) -> Report:
    """构造一份带 ``health`` 评分小节的健康报告。"""
    return Report(
        command="health",
        started_at=datetime.now(UTC),
        duration_ms=7,
        environment={"admin": True, "history": "C:/tmp/history.jsonl"},
        sections=[
            Section(
                id="health",
                title="健康评分",
                rows=[{"项目": "网关", "得分": f"{total}/100"}],
                findings=list(section_findings or []),
            )
        ],
        findings=list(top_findings or []),
        errors=list(errors or []),
        score=Score(total=total, grade="B", items=[]),
    )


def _fix_result(kind: FixKind, *, findings: list[Finding] | None = None) -> FixResult:
    """构造一次成功的修复结果。"""
    return FixResult(
        kind=kind,
        applied=["20260101T000000000000-abcd"],
        failed=[],
        skipped=[],
        findings=list(findings or []),
    )


# ===========================================================================
# build_auto_report：顺序与合成口径
# ===========================================================================
def test_build_auto_report_runs_before_fix_after_in_order() -> None:
    calls: list[str] = []
    before_top = _finding("BEFORE_TOP", Severity.warn)
    before_section = _finding("BEFORE_SECTION", Severity.critical)
    after_top = _finding("AFTER_TOP", Severity.warn)
    fix_finding = _finding("FIX_APPLIED")
    before = _health_report(40, top_findings=[before_top], section_findings=[before_section])
    after = _health_report(90, top_findings=[after_top])

    def health_builder(**kwargs: Any) -> Report:
        calls.append("health")
        return before if len(calls) == 1 else after

    def fix_applier(kind: FixKind, **kwargs: Any) -> FixResult:
        calls.append("fix")
        assert kind is FixKind.all, "auto 必须修复全部类别"
        return _fix_result(kind, findings=[fix_finding])

    report = auto_cmd.build_auto_report(
        health_builder=health_builder,
        fix_applier=fix_applier,
    )

    assert calls == ["health", "fix", "health"], "顺序必须是 修复前 → 修复 → 修复后"
    assert report.command == "auto"
    assert [section.id for section in report.sections] == ["health-before", "health-after"]
    assert [section.title for section in report.sections] == ["修复前健康评分", "修复后健康评分"]
    assert report.sections[0].rows == before.sections[0].rows
    assert report.sections[1].rows == after.sections[0].rows
    assert report.sections[0].findings == [before_section]
    assert report.score is not None
    assert report.score.total == 90, "score 必须取修复后的评分"
    assert report.findings == [fix_finding, after_top], "顶层结论 = 修复结果 + 修复后结论"
    assert report.environment == after.environment


def test_build_auto_report_merges_errors_from_both_health_runs() -> None:
    before_error = ProbeError(code="timeout", source="ping", message="修复前超时")
    after_error = ProbeError(code="unavailable", source="dns", message="修复后不可用")
    before = _health_report(10, errors=[before_error])
    after = _health_report(80, errors=[after_error])
    reports = iter([before, after])

    report = auto_cmd.build_auto_report(
        health_builder=lambda **kwargs: next(reports),
        fix_applier=lambda kind, **kwargs: _fix_result(kind),
    )

    assert report.errors == [before_error, after_error]


def test_build_auto_report_keeps_none_score() -> None:
    """健康报告没有评分时，auto 的 score 也必须是 ``None``（不用 0 冒充）。"""
    empty = Report(
        command="health",
        started_at=datetime.now(UTC),
        duration_ms=1,
        environment={},
        sections=[],
        findings=[],
        errors=[],
        score=None,
    )

    report = auto_cmd.build_auto_report(
        health_builder=lambda **kwargs: empty,
        fix_applier=lambda kind, **kwargs: _fix_result(kind),
    )

    assert report.score is None
    assert [section.id for section in report.sections] == ["health-before", "health-after"]
    assert all(section.rows == [] and section.findings == [] for section in report.sections)


def test_build_auto_report_passes_run_and_api_to_both_layers() -> None:
    seen: list[tuple[str, dict[str, Any]]] = []
    fake_run: Any = object()
    fake_api: Any = object()

    def health_builder(**kwargs: Any) -> Report:
        seen.append(("health", kwargs))
        return _health_report(50)

    def fix_applier(kind: FixKind, **kwargs: Any) -> FixResult:
        seen.append(("fix", kwargs))
        return _fix_result(kind)

    auto_cmd.build_auto_report(
        run=fake_run,
        api=fake_api,
        health_builder=health_builder,
        fix_applier=fix_applier,
    )

    expected = {"run": fake_run, "api": fake_api}
    assert seen == [("health", expected), ("fix", expected), ("health", expected)]


def test_build_auto_report_filters_none_injections() -> None:
    """未注入 run/api 时不能把 ``None`` 传给零参假实现。"""
    calls: list[str] = []

    def zero_arg_health() -> Report:
        calls.append("health")
        return _health_report(50)

    def kind_only_fix(kind: FixKind) -> FixResult:
        calls.append("fix")
        return _fix_result(kind)

    auto_cmd.build_auto_report(
        health_builder=zero_arg_health,
        fix_applier=kind_only_fix,
    )

    assert calls == ["health", "fix", "health"]


def _step(description: str = "设置 DNS", kind: str = "dns", target: str = "以太网") -> FixStep:
    """构造一步最小修复计划。"""
    return FixStep(
        description=description,
        kind=kind,
        target=target,
        before={"servers": []},
        after={"servers": ["223.5.5.5"]},
        undo=[],
    )


# ===========================================================================
# build_auto_report：dry-run 只出计划
# ===========================================================================
def test_build_auto_report_dry_run_plans_without_applying() -> None:
    calls: list[str] = []
    before_top = _finding("BEFORE_TOP", Severity.warn)
    plan_finding = _finding("PLAN_NOTE", Severity.info)
    before = _health_report(40, top_findings=[before_top])
    plan = FixPlan(
        steps=[_step(), _step("调整 TCP", "tcp", "netsh int tcp set global")],
        findings=[plan_finding],
    )

    def health_builder(**kwargs: Any) -> Report:
        calls.append("health")
        return before

    def fix_applier(kind: FixKind, **kwargs: Any) -> FixResult:
        calls.append("fix")
        raise AssertionError("dry-run 不得执行修复")

    def plan_builder(kind: FixKind, **kwargs: Any) -> FixPlan:
        calls.append("plan")
        assert kind is FixKind.all, "dry-run 也必须规划全部类别"
        return plan

    report = auto_cmd.build_auto_report(
        health_builder=health_builder,
        fix_applier=fix_applier,
        plan_builder=plan_builder,
        dry_run=True,
    )

    assert calls == ["health", "plan"], "顺序必须是 修复前诊断 → 生成计划，不得 apply"
    assert report.command == "auto"
    assert [section.id for section in report.sections] == ["health-before", "fix-plan"]
    assert [section.title for section in report.sections] == ["修复前健康评分", "修复计划"]
    assert report.sections[1].rows == [
        {"description": "设置 DNS", "kind": "dns", "target": "以太网"},
        {
            "description": "调整 TCP",
            "kind": "tcp",
            "target": "netsh int tcp set global",
        },
    ]
    assert [finding.code for finding in report.findings] == ["PLAN_NOTE", "AUTO_DRY_RUN"]
    assert report.score is before.score, "dry-run 没有复测，score 沿用修复前"
    assert report.environment == before.environment
    assert report.errors == []


def test_build_auto_report_dry_run_keeps_blocked_plan_visible() -> None:
    """计划被阻塞时：blocked_reason 进 fix-plan 行，计划结论原样保留。"""
    blocked = _finding("SYSTEM_UNAVAILABLE", Severity.warn)
    plan = FixPlan(steps=[], findings=[blocked], blocked_reason="未找到可配置 DNS 的主接口")

    report = auto_cmd.build_auto_report(
        health_builder=lambda **kwargs: _health_report(30),
        fix_applier=lambda kind, **kwargs: pytest.fail("dry-run 不得执行修复"),
        plan_builder=lambda kind, **kwargs: plan,
        dry_run=True,
    )

    assert report.sections[1].rows == [
        {
            "description": "计划被阻塞：未找到可配置 DNS 的主接口",
            "kind": "blocked",
            "target": "",
        }
    ]
    assert blocked in report.findings


def test_build_auto_report_dry_run_forwards_run_and_api() -> None:
    """run / api 同时透传给诊断与计划（None 仍要过滤掉）。"""
    seen: list[tuple[str, dict[str, Any]]] = []
    fake_run: Any = object()
    fake_api: Any = object()

    def health_builder(**kwargs: Any) -> Report:
        seen.append(("health", kwargs))
        return _health_report(50)

    def plan_builder(kind: FixKind, **kwargs: Any) -> FixPlan:
        seen.append(("plan", kwargs))
        return FixPlan(steps=[_step()], findings=[])

    auto_cmd.build_auto_report(
        run=fake_run,
        api=fake_api,
        health_builder=health_builder,
        plan_builder=plan_builder,
        dry_run=True,
    )

    expected = {"run": fake_run, "api": fake_api}
    assert seen == [("health", expected), ("plan", expected)]


def test_build_auto_report_falls_back_to_last_section() -> None:
    """健康报告没有 ``id="health"`` 小节时，退回最后一个小节（只改 id/title）。"""
    other = Section(id="other", title="别的节", rows=[{"项目": "x", "得分": "1"}])
    report = Report(
        command="health",
        started_at=datetime.now(UTC),
        duration_ms=1,
        environment={},
        sections=[other],
        findings=[],
        errors=[],
        score=Score(total=60, grade="C", items=[]),
    )

    built = auto_cmd.build_auto_report(
        health_builder=lambda **kwargs: report,
        fix_applier=lambda kind, **kwargs: _fix_result(kind),
    )

    assert built.sections[0].id == "health-before"
    assert built.sections[0].title == "修复前健康评分"
    assert built.sections[0].rows == other.rows


# ===========================================================================
# CLI：权限门与接线
# ===========================================================================
def _auto_report(total: int = 90, *, critical: bool = False) -> Report:
    findings = [_finding("FIX_FAILED", Severity.critical)] if critical else []
    return Report(
        command="auto",
        started_at=datetime.now(UTC),
        duration_ms=12,
        environment={"admin": True},
        sections=[Section(id="health-after", title="修复后健康评分")],
        findings=findings,
        errors=[],
        score=Score(total=total, grade="B", items=[]),
    )


def test_auto_non_admin_exits_3_without_building(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(undo_cmd, "is_admin", lambda: False)

    def boom(**kwargs: Any) -> Report:
        raise AssertionError("非管理员不得进入诊断/修复")

    monkeypatch.setattr(auto_cmd, "build_auto_report", boom)

    result = runner.invoke(cli.app, ["auto", "--json"])

    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["command"] == "auto"
    assert payload["errors"][0]["code"] == "denied"
    assert payload["findings"][0]["code"] == "PERMISSION_DENIED"
    assert payload["score"] is None


def test_auto_non_admin_text_mentions_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(undo_cmd, "is_admin", lambda: False)

    def boom(**kwargs: Any) -> Report:
        raise AssertionError("非管理员不得进入诊断/修复")

    monkeypatch.setattr(auto_cmd, "build_auto_report", boom)

    result = runner.invoke(cli.app, ["auto"])

    assert result.exit_code == 3
    assert "管理员" in result.stdout


def test_auto_as_admin_runs_and_outputs_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(undo_cmd, "is_admin", lambda: True)
    monkeypatch.setattr(auto_cmd, "build_auto_report", lambda: _auto_report(90))

    result = runner.invoke(cli.app, ["auto", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "auto"
    assert payload["score"]["total"] == 90
    assert payload["sections"][0]["id"] == "health-after"


def test_auto_critical_finding_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(undo_cmd, "is_admin", lambda: True)
    monkeypatch.setattr(auto_cmd, "build_auto_report", lambda: _auto_report(10, critical=True))

    result = runner.invoke(cli.app, ["auto", "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["findings"][0]["code"] == "FIX_FAILED"


def test_auto_dry_run_non_admin_does_not_require_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """非管理员也能 dry-run：不执行修复，因此不做权限门。"""
    monkeypatch.setattr(undo_cmd, "is_admin", lambda: False)
    seen: list[dict[str, Any]] = []

    def fake_build(**kwargs: Any) -> Report:
        seen.append(kwargs)
        return _auto_report(90)

    monkeypatch.setattr(auto_cmd, "build_auto_report", fake_build)

    result = runner.invoke(cli.app, ["auto", "--dry-run", "--json"])

    assert result.exit_code == 0
    assert seen == [{"dry_run": True}], "CLI 必须把 --dry-run 透传给命令层"
    payload = json.loads(result.stdout)
    assert payload["command"] == "auto"


def test_auto_dry_run_as_admin_still_passes_dry_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(undo_cmd, "is_admin", lambda: True)
    seen: list[dict[str, Any]] = []

    def fake_build(**kwargs: Any) -> Report:
        seen.append(kwargs)
        return _auto_report(80)

    monkeypatch.setattr(auto_cmd, "build_auto_report", fake_build)

    result = runner.invoke(cli.app, ["auto", "--dry-run"])

    assert result.exit_code == 0
    assert seen == [{"dry_run": True}]


def test_auto_without_dry_run_still_gates_non_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """回归：没有 --dry-run 时非管理员仍返回 3 且不进入构建。"""
    monkeypatch.setattr(undo_cmd, "is_admin", lambda: False)
    monkeypatch.setattr(
        auto_cmd,
        "build_auto_report",
        lambda **kwargs: pytest.fail("非管理员不得进入诊断/修复"),
    )

    result = runner.invoke(cli.app, ["auto"])

    assert result.exit_code == 3
    assert "管理员" in result.stdout
