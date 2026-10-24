# -*- coding: utf-8 -*-
"""v2 命令层公开出口。

命令层只负责「探测 → Report」：调用 :mod:`netopt.probes` 拿数据，
按 :class:`netopt.domain.policy.Policy` 分档，组装出
:class:`netopt.domain.report.Report`。它**不打印、不渲染、不解析命令行参数**；
渲染与退出码属于 ``netopt.cli`` / ``netopt.render``。
"""

from __future__ import annotations

from netopt.commands.auto import build_auto_report
from netopt.commands.dns import build_dns_report
from netopt.commands.fix import (
    FixKind,
    FixPlan,
    FixResult,
    FixStep,
    apply_fix,
    plan_fix,
)
from netopt.commands.full import build_full_report
from netopt.commands.health import build_health_report
from netopt.commands.http import build_http_report
from netopt.commands.ping import build_ping_report
from netopt.commands.speed import build_speed_report
from netopt.commands.status import build_status_report
from netopt.commands.trace import build_trace_report
from netopt.commands.undo import UndoResult, undo_last
from netopt.commands.watch import WatchSample, run_watch
from netopt.commands.wifi import build_wifi_report

__all__ = [
    "FixKind",
    "FixPlan",
    "FixResult",
    "FixStep",
    "UndoResult",
    "WatchSample",
    "apply_fix",
    "build_auto_report",
    "build_dns_report",
    "build_full_report",
    "build_health_report",
    "build_http_report",
    "build_ping_report",
    "build_speed_report",
    "build_status_report",
    "build_trace_report",
    "build_wifi_report",
    "plan_fix",
    "run_watch",
    "undo_last",
]
