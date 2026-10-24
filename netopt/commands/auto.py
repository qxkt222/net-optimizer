# -*- coding: utf-8 -*-
"""``auto`` 命令 —— 一键优化：诊断 → 自动修复全部 → 复测对比。

职责边界（``docs/SPEC.md`` §11、``docs/TASKS.md`` T4.7）：

- **只做编排**：三份结果分别由健康 builder 与修复层产出，本模块不新增探测、
  阈值或修复逻辑；
- **顺序固定**：先 ``build_health_report`` 存下修复前评分，再
  ``apply_fix(FixKind.all)``，最后再跑一次 ``build_health_report``；
- **dry-run 只出计划**：``dry_run=True`` 时修复前健康报告之后调用
  ``plan_fix(FixKind.all)``，把计划放进 ``fix-plan`` 小节，**不执行修复**；
- **不打印**：返回 :class:`Report`，由 ``netopt.cli`` 统一渲染；
- **失败不吞**：两次健康报告的 ``errors`` 与修复层的 ``findings`` 原样汇总；
- **可注入**：``health_builder`` / ``fix_applier`` / ``plan_builder`` 允许测试
  替换；默认值在 ``def`` 处绑定，显式传入时优先使用注入实现。

权限约定：本模块**不检查管理员权限**。写操作前的权限门属于 CLI
（``netopt.cli`` 沿用 ``netopt.commands.undo.is_admin``），这样命令层
可以被直接调用而不会隐式提权或静默跳过修复。
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from netopt.commands.fix import FixKind, FixPlan, FixResult, apply_fix, plan_fix
from netopt.commands.health import build_health_report
from netopt.domain import Finding, Report, Section, Severity
from netopt.platform import Runner
from netopt.system import SystemApi

__all__ = ["build_auto_report"]

#: 健康报告 builder：真实实现接受 ``run`` / ``api`` 等关键字，假实现可以零参。
ReportBuilder = Callable[..., Report]

#: 修复执行器：第一个参数是 :class:`FixKind`，其余为可选注入参数。
FixApplier = Callable[..., FixResult]

#: 计划生成器：签名与 :func:`netopt.commands.fix.plan_fix` 一致。
PlanBuilder = Callable[..., FixPlan]

#: dry-run 的标记结论码（FindingCode 尚无修复类成员，见 fix.py 的同一约定）。
_DRY_RUN_CODE = "AUTO_DRY_RUN"


def _injected(**kwargs: Any) -> dict[str, Any]:
    """过滤掉值为 ``None`` 的注入参数。

    真实 builder 收到 ``None`` 时本来就会使用默认值，过滤后语义不变；
    零参的假 builder（测试常用）也因此无需声明 ``run`` / ``api`` 形参。
    """
    return {key: value for key, value in kwargs.items() if value is not None}


def _health_section(report: Report, *, section_id: str, title: str) -> Section:
    """从健康报告里取评分小节并改名成 ``health-before`` / ``health-after``。

    优先找 ``id="health"`` 的小节（:func:`build_health_report` 的产物）；
    找不到时退回最后一个小节，保证注入的简化报告也能展示；报告没有任何
    小节时返回一个空小节（不把顶层 findings 复制进来，避免重复）。
    """
    source: Section | None = None
    for section in report.sections:
        if section.id == "health":
            source = section
            break
    if source is None and report.sections:
        source = report.sections[-1]
    if source is None:
        return Section(id=section_id, title=title)
    return source.model_copy(update={"id": section_id, "title": title})


def _plan_section(plan: FixPlan) -> Section:
    """把修复计划渲染成 ``fix-plan`` 小节：每一步一行。

    行里只放展示所需的描述 / 类型 / 目标；完整计划（含 before/after/undo）
    属于修复层，不复制进报告，避免 ``Report`` 承载不可序列化的内部结构。
    """
    rows: list[dict[str, Any]] = [
        {
            "description": step.description,
            "kind": step.kind,
            "target": step.target,
        }
        for step in plan.steps
    ]
    if plan.blocked_reason is not None:
        rows.append(
            {
                "description": f"计划被阻塞：{plan.blocked_reason}",
                "kind": "blocked",
                "target": "",
            }
        )
    return Section(id="fix-plan", title="修复计划", rows=rows)


def build_auto_report(
    *,
    run: Runner | None = None,
    api: SystemApi | None = None,
    health_builder: ReportBuilder = build_health_report,
    fix_applier: FixApplier = apply_fix,
    plan_builder: PlanBuilder = plan_fix,
    dry_run: bool = False,
) -> Report:
    """执行「诊断 → 修复全部 → 复测」并合成一份 ``command="auto"`` 的报告。

    ``dry_run=True`` 时只做修复前诊断并生成修复计划：不调用 ``fix_applier``，
    报告只有 ``health-before`` 与 ``fix-plan`` 两节，追加一条 ``AUTO_DRY_RUN``
    结论说明未执行任何修改。

    非 dry-run 的合成口径：

    - ``sections``：恰好两节，``health-before``（修复前）与 ``health-after``
      （修复后），内容复用各自健康报告的评分小节；
    - ``score``：取**修复后**的评分（before 只用于对比展示）；
    - ``findings``：修复结果在前、修复后健康结论在后；
    - ``errors``：两次健康报告的探测错误依次拼接；
    - ``duration_ms``：本函数实际墙钟耗时（包含修复过程）。
    """
    started_at = datetime.now(UTC)
    started = time.perf_counter()

    injected = _injected(run=run, api=api)
    before = health_builder(**injected)

    if dry_run:
        plan = plan_builder(FixKind.all, **injected)
        dry_run_finding = Finding(
            code=_DRY_RUN_CODE,
            severity=Severity.info,
            title="dry-run：仅生成修复计划",
            detail=f"计划共 {len(plan.steps)} 步；未执行修复、未写变更日志。",
        )
        return Report(
            command="auto",
            started_at=started_at,
            duration_ms=round((time.perf_counter() - started) * 1000),
            environment=dict(before.environment),
            sections=[
                _health_section(before, section_id="health-before", title="修复前健康评分"),
                _plan_section(plan),
            ],
            findings=[*plan.findings, dry_run_finding],
            errors=list(before.errors),
            score=before.score,
        )

    fix_result = fix_applier(FixKind.all, **injected)
    after = health_builder(**injected)

    return Report(
        command="auto",
        started_at=started_at,
        duration_ms=round((time.perf_counter() - started) * 1000),
        environment=dict(after.environment),
        sections=[
            _health_section(before, section_id="health-before", title="修复前健康评分"),
            _health_section(after, section_id="health-after", title="修复后健康评分"),
        ],
        findings=[*fix_result.findings, *after.findings],
        errors=[*before.errors, *after.errors],
        score=after.score,
    )
