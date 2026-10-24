# -*- coding: utf-8 -*-
"""告警规则引擎 —— 把每轮 :class:`Finding` 变成不重复轰炸的 :class:`Alert`。

对应 ``docs/SPEC.md`` §13 与 ``docs/TASKS.md`` T6.2。本模块只做**纯规则判定**：

- 不通知、不弹窗、不写文件、不打印、不 sleep；
- 时间只来自构造时注入的 ``now``（默认 :func:`time.monotonic`），
  因此测试可以用可控时钟逐秒推进；
- 输入是**当前一轮**的全部 Finding，输出是**本轮该发**的告警列表。

同一 ``code`` 的生命周期：

1. 首次出现且严重度达到规则门槛 → 立即告警；
2. 冷却期内再次出现 → 不告警，但累计次数；
3. 冷却期过后仍然存在 → 再告警，``count`` 为自上次通知以来的累计次数；
4. 本轮消失 → 清掉状态；规则要求时额外返回一条 ``active=False`` 的恢复告警。

``count`` 的口径是「自上次发出该 code 的告警以来，出现过多少个采样轮次」
（同一轮内重复出现只算一次）。发出告警后计数归零，恢复告警携带的是
自上次（活动）告警以来累计的次数。

未在 ``rules`` 里列出的 code 一律忽略：**显式规则取代默认规则**，
而不是叠加。只有 ``rules is None`` 时才启用「所有 warn/critical、
冷却 300 秒」的默认规则。
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from netopt.domain import Finding, Severity

# Severity 是 StrEnum，字符串排序不可靠（"critical" < "warn" 只是巧合），
# 且将来加档位就会失效，因此显式给出序数。
_SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.ok: 0,
    Severity.info: 1,
    Severity.warn: 2,
    Severity.critical: 3,
}

# 默认规则的冷却时长（秒）：SPEC §13 的「避免重复轰炸」。
DEFAULT_COOLDOWN_S: Final[float] = 300.0


@dataclass(frozen=True)
class AlertRule:
    """一条告警规则：哪些 code、什么门槛、多久冷却一次。

    ``notify_on_clear`` 为真时，该 code 从「存在」变为「消失」的那一轮
    额外产生一条 ``active=False`` 的恢复告警（只发一次）。
    """

    code: str
    min_severity: Severity = Severity.warn
    cooldown_s: float = DEFAULT_COOLDOWN_S
    notify_on_clear: bool = False


@dataclass(frozen=True)
class Alert:
    """一条待发出的告警（纯数据，不含任何投递行为）。

    ``active=False`` 表示恢复通知：``code`` 已经不再出现。``count`` 是
    自上次通知以来累计的出现轮次，``title`` / ``detail`` 取该 code 在
    累计窗口内最高严重度那条 Finding 的文案。
    """

    code: str
    severity: Severity
    title: str
    detail: str
    count: int
    active: bool = True


@dataclass
class _Tracked:
    """引擎内部为单个 code 维护的状态；随 code 消失而丢弃。"""

    severity: Severity
    title: str
    detail: str
    pending: int = 0
    last_notified: float | None = None


class AlertEngine:
    """按规则 + 冷却把 Finding 流压缩成告警流。

    引擎是有状态的，但状态只与调用序列和注入的时钟有关：同样的
    ``(规则, 时钟序列, feed 序列)`` 必然得到同样的告警序列。
    """

    def __init__(
        self,
        rules: list[AlertRule] | None = None,
        *,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        # None 表示启用默认规则（warn/critical、冷却 300 秒、不报恢复）；
        # 传入空列表则表示「什么 code 都不告警」，语义上必须与 None 区分。
        self._use_default = rules is None
        self._rules: dict[str, AlertRule] = {
            rule.code: rule for rule in ([] if rules is None else rules)
        }
        self._now = now
        self._state: dict[str, _Tracked] = {}

    # ------------------------------------------------------------------
    # 对外接口
    # ------------------------------------------------------------------
    def feed(self, findings: list[Finding]) -> list[Alert]:
        """处理当前一轮 findings，返回本轮应发出的告警（可能为空）。

        同一 code 一轮出现多次只算一次；取其中严重度最高的一条作为文案
        （并列时保留先出现的那条）。
        """
        now = self._now()
        seen = self._collect(findings)

        # 先处理恢复：本轮不再合格的 code 要清状态并（可选）发恢复告警。
        alerts: list[Alert] = []
        for code in [code for code in self._state if code not in seen]:
            stale = self._state.pop(code)
            rule = self._rule_for(code)
            if rule is not None and rule.notify_on_clear:
                alerts.append(
                    Alert(
                        code=code,
                        severity=stale.severity,
                        title=stale.title,
                        detail=stale.detail,
                        count=stale.pending,
                        active=False,
                    )
                )

        for code, finding in seen.items():
            rule = self._rule_for(code)
            if rule is None:  # pragma: no cover - _collect 已过滤过
                continue
            tracked: _Tracked | None = self._state.get(code)
            if tracked is None:
                tracked = _Tracked(
                    severity=finding.severity,
                    title=finding.title,
                    detail=finding.detail,
                )
                self._state[code] = tracked
            elif _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[tracked.severity]:
                # 冷却窗口内升级：文案跟到最高档，但冷却本身不重置。
                tracked.severity = finding.severity
                tracked.title = finding.title
                tracked.detail = finding.detail

            tracked.pending += 1
            if tracked.last_notified is None or now - tracked.last_notified >= rule.cooldown_s:
                alerts.append(
                    Alert(
                        code=code,
                        severity=tracked.severity,
                        title=tracked.title,
                        detail=tracked.detail,
                        count=tracked.pending,
                    )
                )
                tracked.last_notified = now
                tracked.pending = 0

        return alerts

    def active_codes(self) -> set[str]:
        """当前仍处于「存在」状态的 code 集合（不含已消失/被忽略的）。"""
        return set(self._state)

    def reset(self) -> None:
        """丢弃全部状态（含冷却计时），下一次出现会立即告警。"""
        self._state.clear()

    # ------------------------------------------------------------------
    # 内部实现
    # ------------------------------------------------------------------
    def _rule_for(self, code: str) -> AlertRule | None:
        """查 code 对应的规则；默认模式下自动生成一条兜底规则。"""
        if self._use_default:
            return AlertRule(code=code)
        return self._rules.get(code)

    def _collect(self, findings: list[Finding]) -> dict[str, Finding]:
        """按规则门槛筛选，并按 code 去重（保留最高严重度的一条）。"""
        seen: dict[str, Finding] = {}
        for finding in findings:
            rule = self._rule_for(finding.code)
            if rule is None:
                continue
            if _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[rule.min_severity]:
                continue
            previous = seen.get(finding.code)
            if previous is None or (
                _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[previous.severity]
            ):
                seen[finding.code] = finding
        return seen
