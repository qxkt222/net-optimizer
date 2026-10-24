# -*- coding: utf-8 -*-
"""``trace`` 命令 —— ``tracert`` 原始输出 → :class:`Report`。

职责边界：

- **原样呈现**：不解析跳数、不合并同一跳的多次探测，只把 ``tracert`` 的每一行
  放进 :attr:`Section.rows`（键固定为 ``行``），由渲染层决定样式。
- **不打印**：结果全部交给 ``netopt.render``；CLI / GUI 复用同一份数据。
- **失败不吞**：超时、命令缺失、非零退出码都会写进 ``Report.errors``，并在本节
  产出一条 ``TRACE_FAILED`` 结论；原始输出不塞进 Report（只保留首行摘要做证据）。
- **可注入**：命令执行走 :class:`netopt.platform.Runner`，测试注入 fake runner
  即可，绝不真实执行 ``tracert``。

Finding 码说明：:class:`netopt.domain.codes.FindingCode` 尚无 trace 相关成员，
本模块用模块级常量 :data:`TRACE_FAILED`（与 ``commands/fix.py`` 的处理方式一致）。
"""

from __future__ import annotations

import os
import platform as sys_platform
import time
from datetime import UTC, datetime
from typing import Any

from netopt import platform
from netopt.domain import (
    Evidence,
    Finding,
    ProbeError,
    ProbeErrorCode,
    Report,
    Section,
    Severity,
)
from netopt.platform import CmdResult, Runner

__all__ = ["DEFAULT_TARGET", "PROBE_TIMEOUT_MS", "TRACE_FAILED", "build_trace_report"]

#: 与 v1 ``diag.cmd_trace`` 一致的默认目标。
DEFAULT_TARGET = "www.baidu.com"

#: 单跳等待回复的毫秒数（``tracert -w``，与 v1 一致）。
PROBE_TIMEOUT_MS = 800

#: 追踪失败结论码（``FindingCode`` 暂无对应成员）。
TRACE_FAILED = "TRACE_FAILED"

#: 证据里最多保留多长的命令输出摘要。
_SUMMARY_LIMIT = 200


def _environment() -> dict[str, Any]:
    """运行环境快照：权限 / 解释器 / 系统 / 工作目录 / 探测方式。"""
    return {
        "admin": platform.is_admin(),
        "python": sys_platform.python_version(),
        "platform": sys_platform.platform(),
        "cwd": os.getcwd(),
        "api": "tracert",
    }


def _summary(text: str) -> str:
    """取输出里第一行非空文本并截断，作为给人看的失败证据。"""
    for raw in text.splitlines():
        line = raw.strip()
        if line:
            return line[:_SUMMARY_LIMIT]
    return ""


def _error_for(res: CmdResult, budget_seconds: float) -> ProbeError:
    """把一次失败的命令结果翻译成 :class:`ProbeError`。

    - 超时 → ``timeout``，换时机重试有意义；
    - 命令不存在 → ``missing``，重试无用；
    - 其它非零退出码（目标不可达 / 解析失败等）→ ``network``。
    """
    if res.timed_out:
        return ProbeError(
            code=ProbeErrorCode.TIMEOUT,
            source="tracert",
            message=f"tracert 执行超时（超过 {budget_seconds:g} 秒）",
            retryable=True,
        )
    if res.missing:
        return ProbeError(
            code=ProbeErrorCode.MISSING,
            source="tracert",
            message="系统没有 tracert 命令",
        )
    return ProbeError(
        code=ProbeErrorCode.NETWORK,
        source="tracert",
        message=f"tracert 未正常完成（rc={res.code}）",
    )


def _failure_finding(error: ProbeError, res: CmdResult) -> Finding:
    """追踪失败时的一条结论；detail 带上输出首行，方便定位是解析失败还是不可达。"""
    detail = error.message
    summary = _summary(res.out)
    if summary:
        detail = f"{detail}：{summary}"
    return Finding(
        code=TRACE_FAILED,
        severity=Severity.warn,
        title="路由追踪未完成",
        detail=detail,
        advice=[
            "确认目标地址拼写正确且能正常访问",
            "检查本机网络连接后重试",
            "目标屏蔽 ICMP 时 tracert 可能只能显示部分跳数",
        ],
        evidence=[Evidence(source="tracert", detail=summary or None)],
    )


def build_trace_report(
    target: str | None = None,
    *,
    run: Runner | None = None,
    max_hops: int = 20,
    budget_seconds: float = 120.0,
) -> Report:
    """执行一次路由追踪并返回 :class:`Report`。

    ``run`` 默认在**调用时**解析为 :func:`netopt.platform.run`（便于测试注入），
    ``budget_seconds`` 同时作为子进程超时。成功时 ``tracert`` 的每一行原样进入
    ``rows``（键为 ``行``）；失败时产出 ``TRACE_FAILED`` 结论与一条 ``ProbeError``。
    """
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    runner = run if run is not None else platform.run
    host = target if target else DEFAULT_TARGET
    argv = ["tracert", "-d", "-h", str(max_hops), "-w", str(PROBE_TIMEOUT_MS), host]

    res = runner(argv, timeout=budget_seconds)

    rows: list[dict[str, Any]] = []
    findings: list[Finding] = []
    errors: list[ProbeError] = []
    if res.ok:
        # 逐行保留原文；空白行不进入报告（不携带任何跳数信息）。
        rows = [{"行": line} for line in res.out.splitlines() if line.strip()]
    else:
        error = _error_for(res, budget_seconds)
        errors.append(error)
        findings.append(_failure_finding(error, res))

    duration_ms = round((time.perf_counter() - started) * 1000)
    section = Section(id="trace", title="路由追踪", rows=rows, findings=findings)
    return Report(
        command="trace",
        started_at=started_at,
        duration_ms=duration_ms,
        environment=_environment(),
        sections=[section],
        findings=list(findings),
        errors=errors,
    )
