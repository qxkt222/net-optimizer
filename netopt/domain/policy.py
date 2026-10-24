# -*- coding: utf-8 -*-
"""阈值策略 —— v2 中所有“快/慢、好/坏”判断的**唯一真值点**。

v1 存在 4 套互相矛盾的延迟标准（diag/health 各写一份，30/100、30/150、
>80 混用）。v2 把它们收敛成一份 :class:`Policy`：探测层填
``Metric.good/warn``，渲染层只读这两个字段，分析层的分档也走
:meth:`Band.classify`。

本模块只做阈值分档，不产出结论、不写建议文案 —— 业务判断属于
``analysis`` 层。
"""

from __future__ import annotations

import math
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from netopt.domain.report import Severity

_FROZEN = ConfigDict(frozen=True, extra="ignore")

#: 五项权重（合计 90），与 v1 ``netopt/health.py`` 的 WEIGHT_* 常量一致。
DEFAULT_WEIGHTS: Final[dict[str, int]] = {
    "gateway": 15,
    "wan": 25,
    "dns": 20,
    "http": 20,
    "mtu": 10,
}


class Band(BaseModel):
    """三档阈值：``good`` → ``warn`` → ``poor``，单位由使用方决定（本仓库是毫秒）。

    必须满足 ``0 <= good < warn < poor``；分档规则见 :meth:`classify`。
    """

    model_config = _FROZEN

    good: float
    warn: float
    poor: float

    @model_validator(mode="after")
    def _check_order(self) -> Band:
        if not 0 <= self.good < self.warn < self.poor:
            raise ValueError(
                "阈值必须满足 0 <= good < warn < poor，"
                f"实际为 good={self.good} warn={self.warn} poor={self.poor}"
            )
        return self

    def classify(self, value: float | None) -> Severity:
        """把测量值分档。

        - ``None`` / ``NaN`` → ``warn``：测量缺失既不是正常，也不该升级成
          critical；调用方应在 ``Metric.note`` 里说明缺失原因。
        - ``value <= good`` → ``ok``
        - ``value <= warn`` → ``info``
        - ``value <= poor`` → ``warn``
        - ``value > poor`` → ``critical``
        """
        if value is None or math.isnan(value):
            return Severity.warn
        if value <= self.good:
            return Severity.ok
        if value <= self.warn:
            return Severity.info
        if value <= self.poor:
            return Severity.warn
        return Severity.critical


class LossPolicy(BaseModel):
    """丢包率阈值（百分比）。

    ``tolerate``：允许的丢包上限，不超过即视为正常；
    ``unusable``：达到即视为链路基本不可用。
    """

    model_config = _FROZEN

    tolerate: float = 2
    unusable: float = 50

    @model_validator(mode="after")
    def _check_order(self) -> LossPolicy:
        if not 0 <= self.tolerate < self.unusable:
            raise ValueError(
                "丢包阈值必须满足 0 <= tolerate < unusable，"
                f"实际为 tolerate={self.tolerate} unusable={self.unusable}"
            )
        return self


class MtuPolicy(BaseModel):
    """MTU 档位（字节）。

    ``standard``：标准以太网 MTU；``pppoe``：PPPoE 封装后的常见值
    （1500 - 8）；``low``：低于此值对大包影响明显。
    """

    model_config = _FROZEN

    standard: int = 1500
    pppoe: int = 1492
    low: int = 1400

    @model_validator(mode="after")
    def _check_order(self) -> MtuPolicy:
        if not 0 < self.low < self.pppoe < self.standard:
            raise ValueError(
                "MTU 档位必须满足 0 < low < pppoe < standard，"
                f"实际为 low={self.low} pppoe={self.pppoe} standard={self.standard}"
            )
        return self


class Policy(BaseModel):
    """整套阈值与权重。默认值即 v1 行为，改默认值等于改产品行为。

    渲染层与探测层都不应再出现阈值字面量：探测层从这里取
    ``good/warn`` 填进 :class:`~netopt.domain.report.Metric`，分析层调用
    对应 ``Band.classify`` 分档。
    """

    model_config = _FROZEN

    gateway: Band = Field(default_factory=lambda: Band(good=5, warn=30, poor=50))
    wan: Band = Field(default_factory=lambda: Band(good=30, warn=100, poor=150))
    dns: Band = Field(default_factory=lambda: Band(good=30, warn=100, poor=200))
    http_ttfb: Band = Field(default_factory=lambda: Band(good=150, warn=500, poor=1000))
    loss: LossPolicy = Field(default_factory=LossPolicy)
    mtu: MtuPolicy = Field(default_factory=MtuPolicy)
    weights: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    @model_validator(mode="after")
    def _check_weights(self) -> Policy:
        if not self.weights:
            raise ValueError("weights 不能为空")
        bad = {key: weight for key, weight in self.weights.items() if weight <= 0}
        if bad:
            raise ValueError(f"权重必须为正整数，非法项: {bad}")
        return self

    @classmethod
    def default(cls) -> Policy:
        """返回默认策略（等价于 ``Policy()``），便于调用方显式表达意图。"""
        return cls()


__all__ = ["DEFAULT_WEIGHTS", "Band", "LossPolicy", "MtuPolicy", "Policy"]
