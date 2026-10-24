# -*- coding: utf-8 -*-
"""``full`` 命令 —— 全面诊断：status + speed + trace + wifi 合成一份报告。

职责边界：

- **不重复探测**：四份子报告分别由各自的 builder 产出，本模块只做拼接，
  不新增任何探测、阈值或分档逻辑；
- **不打印**：返回 :class:`Report`，由 ``netopt.cli`` / ``netopt.render``
  统一消费，终端与 JSON 输出共用同一份数据；
- **失败不吞**：子报告的 ``findings`` / ``errors`` 原样汇总，任何探测失败都
  能在 ``full`` 报告里看到；
- **可注入**：四个 builder 默认在**调用时**从本模块的全局名解析（而不是在
  ``def`` 处提前绑定函数），因此测试 monkeypatch ``full.build_status_report``
  之类的名字即可生效；也可显式传入假 builder，本模块本身不联网、不执行命令。

合成口径：

- ``sections``：按 status → speed → trace → wifi 顺序拼接；
- ``findings``：四份报告的顶层 ``findings`` 依次拼接（各节结论仍留在
  对应 ``Section.findings`` 内，不重复搬到顶层）；
- ``errors``：四份报告的 ``errors`` 依次拼接；
- ``duration_ms``：四份报告 ``duration_ms`` 之和，不重复计时；
- ``score``：沿用 status 报告的分数（若 status 提供了 ``score``）；
- ``environment``：沿用 status 的环境快照（其余子命令的环境字段并无可比性）。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from netopt.commands.speed import build_speed_report
from netopt.commands.status import build_status_report
from netopt.commands.trace import build_trace_report
from netopt.commands.wifi import build_wifi_report
from netopt.domain import Report
from netopt.platform import Runner
from netopt.system import SystemApi

__all__ = ["build_full_report"]

#: 四个 builder 接受的关键字参数各不相同（run / api），统一按宽签名注入。
ReportBuilder = Callable[..., Report]


def _invoke(builder: ReportBuilder, /, **kwargs: Any) -> Report:
    """调用 builder，只传非 ``None`` 的注入参数。

    真实 builder 在收到 ``None`` 时本来就会使用各自默认值，过滤后语义不变；
    零参的假 builder（测试常用）也因此无需声明 ``run`` / ``api`` 形参。
    """
    return builder(**{key: value for key, value in kwargs.items() if value is not None})


def build_full_report(
    *,
    run: Runner | None = None,
    api: SystemApi | None = None,
    status_builder: ReportBuilder | None = None,
    speed_builder: ReportBuilder | None = None,
    trace_builder: ReportBuilder | None = None,
    wifi_builder: ReportBuilder | None = None,
) -> Report:
    """依次运行四个子诊断并合成一份 ``command="full"`` 的 :class:`Report`。

    ``run`` / ``api`` 透传给接受它们的子 builder：``status`` 两者都收，
    ``trace`` 只收 ``run``，``wifi`` 只收 ``api``，``speed`` 两者都不收。
    ``*_builder`` 为 ``None`` 时在**调用时**解析本模块的全局名，便于测试
    monkeypatch；显式传入时优先使用注入的实现。
    """
    started_at = datetime.now(UTC)
    build_status = status_builder if status_builder is not None else build_status_report
    build_speed = speed_builder if speed_builder is not None else build_speed_report
    build_trace = trace_builder if trace_builder is not None else build_trace_report
    build_wifi = wifi_builder if wifi_builder is not None else build_wifi_report

    status_report = _invoke(build_status, run=run, api=api)
    speed_report = _invoke(build_speed)
    trace_report = _invoke(build_trace, run=run)
    wifi_report = _invoke(build_wifi, api=api)

    reports = (status_report, speed_report, trace_report, wifi_report)
    return Report(
        command="full",
        started_at=started_at,
        duration_ms=sum(report.duration_ms for report in reports),
        environment=dict(status_report.environment),
        sections=[section for report in reports for section in report.sections],
        findings=[finding for report in reports for finding in report.findings],
        errors=[error for report in reports for error in report.errors],
        score=status_report.score,
    )
