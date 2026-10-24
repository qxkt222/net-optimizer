# -*- coding: utf-8 -*-
"""Report 的 JSON 渲染 —— 直接复用 pydantic 序列化，保持与契约逐字段一致。

不做字段裁剪、不重排键、不转义中文：输出即是
:meth:`netopt.domain.report.Report.model_dump_json` 的结果，
消费方（CLI ``--json``、GUI、外部脚本）看到的字段与 ``Report`` 完全相同。
"""

from __future__ import annotations

from netopt.domain.report import Report

__all__ = ["render_json"]


def render_json(report: Report, *, indent: int | None = 2) -> str:
    """把报告序列化为 JSON 文本（UTF-8，中文不转义）。

    ``indent=None`` 时输出单行紧凑 JSON。本函数只返回字符串，不 print，
    保证 stdout 可以被调用方独占。
    """
    return report.model_dump_json(indent=indent)
