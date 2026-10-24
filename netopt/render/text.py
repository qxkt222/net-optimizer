# -*- coding: utf-8 -*-
"""Report 的终端渲染 —— ``Report -> rich 输出``，纯展示层。

分层约束：

- 只读 :class:`netopt.domain.report.Report`，不探测、不读写文件、不改模型；
- 颜色只看 ``Metric.good/warn`` 与 ``Finding.severity``，阈值来自 policy，
  本模块不出现任何业务阈值字面量；
- 不直接 print：``render_report`` 写入调用方给的 ``Console``，
  ``render_plain`` 返回无 ANSI 的纯文本，供 GUI / 日志消费。
"""

from __future__ import annotations

import io
from typing import Any, Final

from rich.console import Console
from rich.table import Table
from rich.text import Text

from netopt.domain.report import Finding, Metric, Report, Section, Severity

__all__ = ["format_value", "render_plain", "render_report"]

#: 严重程度 → 颜色，语义见 SPEC §9.1。
_SEVERITY_STYLE: Final[dict[Severity, str]] = {
    Severity.ok: "green",
    Severity.info: "cyan",
    Severity.warn: "yellow",
    Severity.critical: "red",
}

#: Metric 与自带 ``good`` / ``warn`` 比较后的三档样式。
_METRIC_STYLE: Final[dict[str, str]] = {
    "ok": "green",
    "warn": "yellow",
    "bad": "red",
}

#: 纯文本输出的宽度：够宽以免表格折行，GUI / 日志再自行处理。
_PLAIN_WIDTH: Final[int] = 118

#: 整数型单位：值为整数时不显示小数。
_INT_UNITS: Final[frozenset[str]] = frozenset({"", "个", "次"})

#: ``Section.rows`` 中已知键的中文标签；未知键原样展示，不改写用户数据。
_ROW_LABELS: Final[dict[str, str]] = {
    "ip": "地址",
    "metric": "跃点数",
    "target": "目标",
    "servers": "服务器",
    "ssid": "SSID",
    "channel": "信道",
    "band": "频段",
}


def _admin_text(report: Report) -> str:
    """把 ``environment["admin"]`` 转成给人看的文字；缺失即“未知”。"""
    admin = report.environment.get("admin")
    if admin is True:
        return "是"
    if admin is False:
        return "否"
    return "未知"


def format_value(value: float | None, unit: str) -> str:
    """数值 + 单位，按单位选择合理精度。

    规则：

    - ``None`` → ``"-"``，不用 0 / -1 冒充缺失；
    - ``ms`` / ``%`` → 1 位小数（如 ``24.2083`` → ``24.2 ms``）；
    - ``Mbps`` → 2 位小数；
    - ``""`` / ``个`` / ``次`` 且值为整数 → 不带小数（如 ``1.0`` → ``1``）；
    - 其他单位 → ``g`` 格式，保留有效数字。
    """
    if value is None:
        return "-"
    if unit in {"ms", "%"}:
        number = f"{value:.1f}"
    elif unit == "Mbps":
        number = f"{value:.2f}"
    elif unit in _INT_UNITS and float(value).is_integer():
        number = str(int(value))
    else:
        number = f"{value:g}"
    return f"{number} {unit}".strip()


def _metric_status(metric: Metric) -> tuple[str, str]:
    """返回 ``(状态文字, rich 样式)``。

    判定只依赖 :class:`Metric` 自带的 ``good`` / ``warn``：不超过 ``good`` 为
    ok，不超过 ``warn`` 为 warn，其余为 bad。渲染层不持有任何阈值。
    """
    if not metric.available or metric.value is None:
        return "不可用", "dim"
    if metric.good is None and metric.warn is None:
        return "—", "dim"
    if metric.good is not None and metric.value <= metric.good:
        return "ok", _METRIC_STYLE["ok"]
    if metric.warn is not None and metric.value <= metric.warn:
        return "warn", _METRIC_STYLE["warn"]
    return "bad", _METRIC_STYLE["bad"]


def _cell(value: object) -> str:
    """把 rows 里的任意值转成文本；``None`` 显示为空，列表用逗号连接。"""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    return str(value)


def _metric_table(section: Section) -> Table:
    """构造本节指标表：指标 / 数值+单位 / 状态。"""
    table = Table(show_header=True, header_style="bold", expand=False)
    table.add_column("指标", style="bold", no_wrap=True)
    table.add_column("数值")
    table.add_column("状态", justify="center", no_wrap=True)
    for metric in section.metrics:
        status, style = _metric_status(metric)
        table.add_row(
            metric.label, format_value(metric.value, metric.unit), Text(status, style=style)
        )
    return table


def _print_rows(console: Console, rows: list[dict[str, Any]]) -> None:
    """用「中文标签：值」的紧凑列表输出键值行。

    已知键映射成中文标签（``ip`` → 地址 等），未知键原样显示，
    不再出现 ``key`` / ``value`` 之类的英文表头。
    """
    for row in rows:
        parts = [f"{_ROW_LABELS.get(key, key)}：{_cell(value)}" for key, value in row.items()]
        console.print(Text(" · ".join(parts)))


def _print_finding(console: Console, finding: Finding) -> None:
    """输出一条结论：严重程度、标题、码、详情、建议与证据。"""
    style = _SEVERITY_STYLE[finding.severity]
    header = Text()
    header.append("● ", style=style)
    header.append(finding.severity.value, style=style)
    header.append(" ")
    header.append(finding.title, style=f"bold {style}")
    header.append(f"  ({finding.code})", style="dim")
    console.print(header)
    console.print(Text(f"  {finding.detail}"))
    for advice in finding.advice:
        console.print(Text(f"    · {advice}"))
    for evidence in finding.evidence:
        line = Text("    证据 ")
        line.append(evidence.source)
        if evidence.detail is not None:
            line.append(f"：{evidence.detail}")
        if evidence.raw_ref is not None:
            line.append(f" [raw_ref={evidence.raw_ref}]", style="dim")
        console.print(line)


def _print_section(console: Console, section: Section) -> None:
    """输出一个小节：标题、指标表、键值表与本节结论。"""
    console.rule(Text(section.title, style="bold"))
    printed = False
    if section.metrics:
        console.print(_metric_table(section))
        printed = True
    if section.rows:
        _print_rows(console, section.rows)
        printed = True
    for finding in section.findings:
        _print_finding(console, finding)
        printed = True
    if not printed:
        console.print(Text("（本节无数据）", style="dim"))


def _print_errors(console: Console, report: Report) -> None:
    """输出探测错误：每条显示 code / source / message。"""
    if not report.errors:
        return
    console.rule(Text("探测错误", style="bold red"))
    for error in report.errors:
        line = Text()
        line.append("✗ ", style="red")
        line.append(error.code, style="bold red")
        line.append(f" · {error.source}：")
        line.append(error.message)
        if error.retryable:
            line.append("（可重试）", style="dim")
        console.print(line)


def _print_findings(console: Console, findings: list[Finding], title: str) -> None:
    """输出一组顶层结论。"""
    if not findings:
        return
    console.rule(Text(title, style="bold"))
    for finding in findings:
        _print_finding(console, finding)


def _render(report: Report, console: Console) -> None:
    """实际渲染入口；``render_report`` 与 ``render_plain`` 共用。"""
    header = Text()
    header.append(report.command, style="bold")
    header.append(f" · 用时 {report.duration_ms} ms · 管理员: {_admin_text(report)}")
    if report.score is not None:
        header.append(f" · 健康分 {report.score.total}（{report.score.grade}）")
    console.print(header)

    if not report.sections:
        console.print(Text("（没有可展示的小节）", style="dim"))
    for section in report.sections:
        _print_section(console, section)

    _print_findings(console, report.findings, "诊断结论")
    _print_errors(console, report)


def render_report(report: Report, *, console: Console | None = None) -> None:
    """把报告渲染到终端。

    未提供 ``console`` 时使用 rich 的默认 ``Console``，因此 ``NO_COLOR``
    环境变量与 ``--no-color`` 由 rich 自身处理，本函数不覆盖颜色设置。
    """
    _render(report, console if console is not None else Console())


def render_plain(report: Report) -> str:
    """返回无 ANSI 转义的纯文本，供 GUI / 日志使用。

    与 :func:`render_report` 使用同一套渲染逻辑，只是写入一个不产生
    控制序列的 ``Console``，因此两者信息一致。
    """
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        no_color=True,
        highlight=False,
        width=_PLAIN_WIDTH,
    )
    _render(report, console)
    return buffer.getvalue()
