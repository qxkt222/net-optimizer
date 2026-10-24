# -*- coding: utf-8 -*-
"""渲染层公开出口：``Report -> 终端文本 / JSON``。

渲染层只消费 :class:`netopt.domain.report.Report`，只读
``Metric.good/warn`` 与 ``Finding.severity`` 决定样式，
不探测、不做业务判断、不写 stdout。
"""

from __future__ import annotations

from netopt.render.json import render_json
from netopt.render.text import format_value, render_plain, render_report

__all__ = ["format_value", "render_json", "render_plain", "render_report"]
