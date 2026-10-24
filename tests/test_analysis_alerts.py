# -*- coding: utf-8 -*-
"""netopt.analysis.alerts 测试：规则门槛、冷却、去重与恢复通知。

全部用例使用可控时钟（``_Clock``），禁止 sleep；预期值按任务书的语义
独立手算并写在注释里，不拿被测引擎的输出反过来当预期。
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from netopt.analysis.alerts import Alert, AlertEngine, AlertRule
from netopt.domain import Finding, Severity


@dataclass
class _Clock:
    """可控单调时钟：测试按需推进，不依赖真实时间。"""

    value: float = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def finding(
    code: str = "WAN_LATENCY_HIGH",
    severity: Severity = Severity.critical,
    title: str = "外网延迟偏高",
    detail: str = "平均 120 ms",
) -> Finding:
    """构造一条最小可用的 Finding。"""
    return Finding(code=code, severity=severity, title=title, detail=detail)


def engine(clock: _Clock, rules: list[AlertRule] | None = None) -> AlertEngine:
    """用可控时钟构造引擎。"""
    return AlertEngine(rules, now=clock)


# ---------------------------------------------------------------------------
# 基本生命周期
# ---------------------------------------------------------------------------
def test_first_critical_alerts_immediately() -> None:
    """首次出现 critical → 立刻告警，count 为 1。"""
    clock = _Clock()
    alerts = engine(clock).feed([finding()])

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.code == "WAN_LATENCY_HIGH"
    assert alert.severity is Severity.critical
    assert alert.title == "外网延迟偏高"
    assert alert.detail == "平均 120 ms"
    assert alert.count == 1
    assert alert.active is True


def test_within_cooldown_is_silent_but_counts() -> None:
    """冷却期内重复 → 不告警；累计数在下次告警时体现。"""
    clock = _Clock()
    alerts_engine = engine(clock)

    assert len(alerts_engine.feed([finding()])) == 1  # t=0，首次告警
    clock.advance(100)  # t=100
    assert alerts_engine.feed([finding()]) == []
    clock.advance(100)  # t=200
    assert alerts_engine.feed([finding()]) == []

    # t=300 恰好达到 300 秒冷却；此前又出现了 2 轮，含本轮共 3 轮。
    clock.advance(100)
    alerts = alerts_engine.feed([finding()])
    assert len(alerts) == 1
    assert alerts[0].count == 3


def test_cooled_down_still_present_alerts_again() -> None:
    """冷却期过后仍存在 → 再告警，count 为该窗口内的累计次数。"""
    clock = _Clock()
    alerts_engine = engine(clock)

    assert len(alerts_engine.feed([finding()])) == 1
    clock.advance(299)
    assert alerts_engine.feed([finding()]) == []  # 差 1 秒，仍在冷却
    clock.advance(1)  # t=300
    alerts = alerts_engine.feed([finding()])

    assert len(alerts) == 1
    assert alerts[0].count == 2  # t=299 与 t=300 两轮


# ---------------------------------------------------------------------------
# 消失与恢复
# ---------------------------------------------------------------------------
def test_disappear_clears_active_codes() -> None:
    """本轮消失 → active_codes 清空；默认规则不发恢复告警。"""
    clock = _Clock()
    alerts_engine = engine(clock)

    alerts_engine.feed([finding()])
    assert alerts_engine.active_codes() == {"WAN_LATENCY_HIGH"}

    assert alerts_engine.feed([]) == []
    assert alerts_engine.active_codes() == set()


def test_notify_on_clear_emits_recovery_alert() -> None:
    """notify_on_clear=True → 消失那一轮返回 active=False 的恢复告警。"""
    clock = _Clock()
    rule = AlertRule(code="WAN_LATENCY_HIGH", notify_on_clear=True)
    alerts_engine = engine(clock, [rule])

    alerts_engine.feed([finding()])
    clock.advance(10)
    alerts_engine.feed([finding()])  # 冷却期内，pending 累计到 1

    alerts = alerts_engine.feed([])
    assert len(alerts) == 1
    assert isinstance(alerts[0], Alert)
    assert alerts[0].active is False
    assert alerts[0].code == "WAN_LATENCY_HIGH"
    assert alerts[0].severity is Severity.critical
    assert alerts[0].count == 1
    assert alerts_engine.active_codes() == set()

    # 恢复通知只发一次。
    assert alerts_engine.feed([]) == []


def test_reappear_after_clear_alerts_immediately() -> None:
    """消失后再出现按全新状态处理：t=500 也立即告警。"""
    clock = _Clock()
    alerts_engine = engine(clock)

    alerts_engine.feed([finding()])
    alerts_engine.feed([])
    clock.advance(500)
    alerts = alerts_engine.feed([finding()])

    assert len(alerts) == 1
    assert alerts[0].count == 1


# ---------------------------------------------------------------------------
# 门槛与默认规则
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("severity", [Severity.ok, Severity.info])
def test_default_rules_ignore_low_severity(severity: Severity) -> None:
    """info / ok 不触发默认规则，也不进入 active_codes。"""
    clock = _Clock()
    alerts_engine = engine(clock)

    assert alerts_engine.feed([finding(severity=severity)]) == []
    assert alerts_engine.active_codes() == set()


def test_warn_triggers_default_rule() -> None:
    """默认规则的门槛是 warn。"""
    clock = _Clock()
    alerts = engine(clock).feed([finding(severity=Severity.warn)])

    assert len(alerts) == 1
    assert alerts[0].severity is Severity.warn


def test_custom_min_severity_only_allows_critical() -> None:
    """自定义规则 min_severity=critical → warn 被忽略，critical 放行。"""
    clock = _Clock()
    rule = AlertRule(code="WAN_LATENCY_HIGH", min_severity=Severity.critical)
    alerts_engine = engine(clock, [rule])

    assert alerts_engine.feed([finding(severity=Severity.warn)]) == []
    assert alerts_engine.active_codes() == set()

    alerts = alerts_engine.feed([finding(severity=Severity.critical)])
    assert len(alerts) == 1


def test_explicit_rules_ignore_unlisted_codes() -> None:
    """给了显式规则后，未列出的 code 不会被默认规则兜底。"""
    clock = _Clock()
    alerts_engine = engine(clock, [AlertRule(code="KNOWN")])

    assert alerts_engine.feed([finding(code="WAN_LATENCY_HIGH")]) == []
    assert alerts_engine.active_codes() == set()

    alerts = alerts_engine.feed([finding(code="KNOWN")])
    assert len(alerts) == 1


def test_empty_rules_list_disables_everything() -> None:
    """空规则列表与 None 语义不同：什么都不告警。"""
    clock = _Clock()
    alerts_engine = engine(clock, [])

    assert alerts_engine.feed([finding()]) == []
    assert alerts_engine.active_codes() == set()


# ---------------------------------------------------------------------------
# 去重与状态
# ---------------------------------------------------------------------------
def test_same_code_twice_in_one_round_yields_one_alert() -> None:
    """同一 code 一轮出现多次 → 只一条告警，count 仍为 1。"""
    clock = _Clock()
    alerts = engine(clock).feed(
        [
            finding(severity=Severity.warn, title="旧"),
            finding(severity=Severity.critical, title="新"),
        ]
    )

    assert len(alerts) == 1
    assert alerts[0].count == 1
    # 同一轮内取最高严重度那条的文案。
    assert alerts[0].severity is Severity.critical
    assert alerts[0].title == "新"


def test_dedupe_keeps_first_on_severity_tie() -> None:
    """严重度并列时保留先出现的一条。"""
    clock = _Clock()
    alerts = engine(clock).feed([finding(title="先"), finding(title="后")])

    assert len(alerts) == 1
    assert alerts[0].title == "先"


def test_multiple_codes_are_independent() -> None:
    """不同 code 各自独立冷却与计数。"""
    clock = _Clock()
    alerts_engine = engine(clock)

    first = alerts_engine.feed([finding(code="A"), finding(code="B")])
    assert {alert.code for alert in first} == {"A", "B"}
    assert alerts_engine.active_codes() == {"A", "B"}

    clock.advance(100)
    second = alerts_engine.feed([finding(code="B")])
    assert second == []
    assert alerts_engine.active_codes() == {"B"}


def test_reset_allows_immediate_realert() -> None:
    """reset() 丢弃冷却状态，下一次出现立即告警。"""
    clock = _Clock()
    alerts_engine = engine(clock)

    assert len(alerts_engine.feed([finding()])) == 1
    alerts_engine.reset()
    assert alerts_engine.active_codes() == set()

    alerts = alerts_engine.feed([finding()])
    assert len(alerts) == 1
    assert alerts[0].count == 1


def test_severity_escalation_updates_payload_without_resetting_cooldown() -> None:
    """冷却期内升级：文案跟到最高档，但不会提前再告警。"""
    clock = _Clock()
    alerts_engine = engine(clock)

    alerts_engine.feed([finding(severity=Severity.warn, title="一般")])
    clock.advance(10)
    assert alerts_engine.feed([finding(severity=Severity.critical, title="严重")]) == []

    clock.advance(290)  # t=300
    alerts = alerts_engine.feed([finding(severity=Severity.warn, title="一般")])
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.critical
    assert alerts[0].title == "严重"
    # t=10 与 t=300 两轮；t=0 的那次已在上一条告警里结算。
    assert alerts[0].count == 2


def test_engine_does_not_mutate_input() -> None:
    """feed 不修改调用方传入的列表。"""
    clock = _Clock()
    items = [finding()]
    before = list(items)

    engine(clock).feed(items)

    assert items == before
