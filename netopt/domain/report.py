# -*- coding: utf-8 -*-
"""Report 与子模型 —— v2 唯一跨命令、跨前端的领域契约。

**冻结契约**：字段名、类型与默认值由 ``docs/SPEC.md`` §5.1 规定。
命令（probes → analysis）产出它，text / json / gui 三条渲染路径消费它。
改动字段语义必须升 ``Report.schema_version``，并同步通知所有消费方。

约定：

- 全部模型 ``frozen=True, extra="ignore"``：产出方不能就地改已产出的报告；
  消费方把带未知字段的新版 JSON 交给旧模型时也不会炸。
- 测量缺失一律 ``value=None`` + ``available=False``，禁止用 ``-1`` / ``0`` 冒充。
- 原始命令输出不进 Report，只在 :class:`Evidence` 里留 ``raw_ref``，
  指向 ``raw/<run_id>/`` 下的文件。
- 本模块只定义数据结构与纯查询方法，不做探测、不读写文件、不打印。
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict

# 所有契约模型共用同一份配置：冻结 + 忽略未知字段。
_FROZEN = ConfigDict(frozen=True, extra="ignore")


class Severity(StrEnum):
    """找见（Finding）的严重程度，同时也是排序与配色的唯一依据。

    - ``ok``：正常，无需处置
    - ``info``：可优化，但不算故障
    - ``warn``：需要关注，可能影响体验
    - ``critical``：明确故障，必须处理
    """

    ok = "ok"
    info = "info"
    warn = "warn"
    critical = "critical"


class ProbeError(BaseModel):
    """一次探测失败的记录。

    ``code`` 取 :class:`netopt.domain.codes.ProbeErrorCode` 的值；
    ``source`` 标明失败来源（如 ``"iphlpapi"`` / ``"ping"`` / ``"dns:223.5.5.5"``）；
    ``retryable`` 表示换个时机重试是否有意义（超时可重试，权限拒绝通常不可）。
    """

    model_config = _FROZEN

    code: str
    source: str
    message: str
    retryable: bool = False


class Metric(BaseModel):
    """一个可量化指标。

    ``good`` / ``warn`` 由 policy 填好，渲染层只读这两个值决定颜色，
    **不得自带阈值**。``value=None`` 且 ``available=False`` 表示没测到；
    ``note`` 用来解释缺失原因或补充口径，不要拿它塞业务结论。
    """

    model_config = _FROZEN

    key: str
    label: str
    value: float | None
    unit: str = ""
    good: float | None = None
    warn: float | None = None
    available: bool = True
    note: str | None = None


class Evidence(BaseModel):
    """支撑一条 Finding 的证据。

    ``detail`` 是给人看的一句话；``raw_ref`` 指向另存的原始输出文件，
    不要把原始文本塞进 Report。
    """

    model_config = _FROZEN

    source: str
    detail: str | None = None
    raw_ref: str | None = None


class Finding(BaseModel):
    """一条诊断结论。

    ``code`` 取 :class:`netopt.domain.codes.FindingCode` 的值，是建议文案的
    唯一分发键 —— 渲染层不得按 ``title`` 做业务判断。
    """

    model_config = _FROZEN

    code: str
    severity: Severity
    title: str
    detail: str
    advice: list[str] = []
    evidence: list[Evidence] = []


class Section(BaseModel):
    """报告中的一节（如“网关”“DNS”“MTU”）。

    ``metrics`` 放可量化项，``rows`` 放非量化的键值表，``findings`` 放
    本节专属结论；顶层的 ``Report.findings`` 用于跨节归因结论。
    """

    model_config = _FROZEN

    id: str
    title: str
    metrics: list[Metric] = []
    rows: list[dict[str, Any]] = []
    findings: list[Finding] = []


#: ``Score.items`` 每项的固定键（与 v1 ``netopt.health.ItemScore`` 对齐）。
#: analysis 层按这个顺序产出，消费方按这个顺序展示；键名不可随意增删。
SCORE_ITEM_KEYS: Final[tuple[str, ...]] = ("label", "score", "weight", "detail")


class Score(BaseModel):
    """健康分。

    ``items`` 是各维度的评分明细，每项形如
    ``{"label": "网关", "score": 15, "weight": 15, "detail": "3 ms / 丢包 0%"}``，
    由 analysis 层填，渲染层只展示不重算。四个键的语义：

    - ``label``（str）：维度显示名，如“网关”“外网”“DNS”“HTTP”“MTU”。
    - ``score``（int）：该维度实际得分，范围 ``0..weight``；测量缺失时为 0。
    - ``weight``（int）：该维度满分，即 ``Policy.weights`` 中的同名权重。
    - ``detail``（str）：给人看的一句话依据，不得作为业务判断的分发键。

    ``total`` 是百分制总分，``grade`` 是档位字母。
    """

    model_config = _FROZEN

    total: int
    grade: str
    items: list[dict[str, Any]]


class Report(BaseModel):
    """一次命令运行的完整结果。

    这是 v2 的**唯一**跨命令、跨前端数据结构：终端、JSON 输出与 GUI 都
    只消费它，不再各自解析原始命令输出。
    """

    model_config = _FROZEN

    schema_version: int = 1
    command: str
    started_at: datetime
    duration_ms: int
    environment: dict[str, Any]
    sections: list[Section]
    findings: list[Finding]
    errors: list[ProbeError]
    score: Score | None = None

    def add_section(self, section: Section) -> Report:
        """返回追加了一节的新报告。

        模型是 frozen 的，不能就地改列表；调用方必须使用返回值。
        """
        return self.model_copy(update={"sections": [*self.sections, section]})

    def to_json(self, indent: int | None = None) -> str:
        """序列化为 JSON 文本；``datetime`` 按 ISO8601 输出。"""
        return self.model_dump_json(indent=indent)

    def critical_findings(self) -> list[Finding]:
        """返回所有 critical 级别的 Finding。

        包含顶层 ``findings`` 与各 ``section.findings``，按出现顺序拼接，
        不做去重 —— 同一 ``code`` 在不同节重复出现是合法信息。
        """
        found = [f for f in self.findings if f.severity is Severity.critical]
        for section in self.sections:
            found.extend(f for f in section.findings if f.severity is Severity.critical)
        return found
