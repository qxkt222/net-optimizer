# -*- coding: utf-8 -*-
"""分析层公开出口。

外部只应从 ``netopt.analysis`` 导入评分与诊断函数；内部模块之间可以继续
按文件导入。本层是纯函数：输入领域数据 + Policy，输出 Report 契约里的
``Score`` / ``Finding``，不做 IO、不打印。
"""

from __future__ import annotations

from netopt.analysis.alerts import Alert, AlertEngine, AlertRule
from netopt.analysis.diagnose import (
    TCP_RETRANSMIT_WARN,
    ConnectivitySnapshot,
    diagnose,
)
from netopt.analysis.health import (
    ItemScore,
    evaluate,
    grade,
    score_dns,
    score_gateway,
    score_http,
    score_mtu,
    score_wan,
    total_score,
)

__all__ = [
    "TCP_RETRANSMIT_WARN",
    "Alert",
    "AlertEngine",
    "AlertRule",
    "ConnectivitySnapshot",
    "ItemScore",
    "diagnose",
    "evaluate",
    "grade",
    "score_dns",
    "score_gateway",
    "score_http",
    "score_mtu",
    "score_wan",
    "total_score",
]
