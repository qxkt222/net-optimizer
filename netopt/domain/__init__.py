# -*- coding: utf-8 -*-
"""领域模型公开出口。

外部只应从 ``netopt.domain`` 导入 Report 契约、Policy 与常量码表；
内部模块之间可以继续按文件导入。
"""

from __future__ import annotations

from netopt.domain.changes import Change, ChangeStatus
from netopt.domain.codes import FindingCode, ProbeErrorCode
from netopt.domain.models import (
    Adapter,
    Address,
    InterfaceDns,
    InterfaceStats,
    PlatformInfo,
    Route,
    WifiNetwork,
    WifiScan,
    WifiState,
)
from netopt.domain.policy import DEFAULT_WEIGHTS, Band, LossPolicy, MtuPolicy, Policy
from netopt.domain.report import (
    SCORE_ITEM_KEYS,
    Evidence,
    Finding,
    Metric,
    ProbeError,
    Report,
    Score,
    Section,
    Severity,
)

__all__ = [
    "DEFAULT_WEIGHTS",
    "SCORE_ITEM_KEYS",
    "Adapter",
    "Address",
    "Band",
    "Change",
    "ChangeStatus",
    "Evidence",
    "Finding",
    "FindingCode",
    "InterfaceDns",
    "InterfaceStats",
    "LossPolicy",
    "Metric",
    "MtuPolicy",
    "PlatformInfo",
    "Policy",
    "ProbeError",
    "ProbeErrorCode",
    "Report",
    "Route",
    "Score",
    "Section",
    "Severity",
    "WifiNetwork",
    "WifiScan",
    "WifiState",
]
