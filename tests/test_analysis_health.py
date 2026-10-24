# -*- coding: utf-8 -*-
"""netopt.analysis.health 测试：评分边界、诊断结论与纯函数性质。

约定（BRIEF §8）：预期值按 v1 ``netopt/health.py`` 的规则**独立手算**
（算式写在注释里），不拿被测函数的输出反过来当预期。本模块不碰 IO，
因此测试里没有任何 runner / monkeypatch。
"""

from __future__ import annotations

import inspect
from collections.abc import Sequence

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netopt.analysis import health
from netopt.analysis.health import ItemScore
from netopt.domain import (
    Band,
    Finding,
    FindingCode,
    LossPolicy,
    MtuPolicy,
    Policy,
    Score,
    Severity,
)
from netopt.models import MtuResult, PingStat

POLICY = Policy.default()


def stat(avg_ms: float | None = None, loss_pct: float = 0.0, target: str = "test") -> PingStat:
    """构造一次 ping 结果（``avg_ms`` 为 None 表示一个回复都没收到）。"""
    return PingStat(
        target=target,
        avg_ms=avg_ms,
        loss_pct=loss_pct,
        replies=0 if avg_ms is None else 4,
    )


def _items(*pairs: tuple[int, int]) -> list[ItemScore]:
    return [
        ItemScore(label=f"L{i}", score=score, weight=weight, detail="d")
        for i, (score, weight) in enumerate(pairs)
    ]


def _codes(findings: Sequence[Finding]) -> list[str]:
    return [finding.code for finding in findings]


def _only(findings: Sequence[Finding], code: FindingCode) -> Finding:
    matched = [finding for finding in findings if finding.code == code]
    assert len(matched) == 1, f"期望恰好一条 {code}，实际 {_codes(findings)}"
    return matched[0]


# ===========================================================================
# 网关：延迟分 × 丢包折扣
# ===========================================================================
class TestScoreGateway:
    def test_good_boundary_is_full(self) -> None:
        assert health.score_gateway(stat(5, 0), POLICY) == 15
        assert health.score_gateway(stat(1, 0), POLICY) == 15

    def test_poor_boundary_scores_zero(self) -> None:
        assert health.score_gateway(stat(50, 0), POLICY) == 0
        # round(15 * 1 / 45) = round(0.33) = 0
        assert health.score_gateway(stat(49, 0), POLICY) == 0

    def test_warn_point_is_still_linear(self) -> None:
        # warn=30 只用于出结论；评分按 5→50 线性：round(15 * 20 / 45) = 7
        assert health.score_gateway(stat(30, 0), POLICY) == 7

    def test_unreachable_is_zero(self) -> None:
        assert health.score_gateway(stat(None, 100), POLICY) == 0

    @pytest.mark.parametrize(
        ("loss", "expected"),
        [
            (0.0, 15),  # 不丢包：保留延迟分
            (2.0, 15),  # 等于 tolerate：保留
            (2.1, 7),  # 略超 tolerate：15 // 2
            (3.0, 7),
            (49.9, 7),  # 仍低于 unusable：减半
            (50.0, 0),  # 等于 unusable：归零
            (100.0, 0),
        ],
    )
    def test_loss_tiers(self, loss: float, expected: int) -> None:
        assert health.score_gateway(stat(5, loss), POLICY) == expected

    def test_loss_tiers_use_policy(self) -> None:
        pol = Policy(loss=LossPolicy(tolerate=5, unusable=80))
        assert health.score_gateway(stat(5, 5), pol) == 15
        assert health.score_gateway(stat(5, 6), pol) == 7
        assert health.score_gateway(stat(5, 80), pol) == 0


# ===========================================================================
# 外网：延迟分（60% 权重）+ 丢包奖励（40% 权重）；默认权重 25 → 15 + 10
# ===========================================================================
class TestScoreWan:
    def test_clean_fast_is_full(self) -> None:
        assert health.score_wan(stat(30, 0), POLICY) == 25
        assert health.score_wan(stat(26, 0), POLICY) == 25

    @pytest.mark.parametrize("weight", [10, 15, 25, 30, 40])
    def test_max_score_equals_policy_weight(self, weight: int) -> None:
        # 满分必须恰好等于权重，不能出现「得分 > 满分」
        pol = Policy(weights={"gateway": 15, "wan": weight, "dns": 20, "http": 20, "mtu": 10})
        assert health.score_wan(stat(30, 0), pol) == weight

    def test_custom_weight_keeps_60_40_split(self) -> None:
        pol = Policy(weights={"gateway": 15, "wan": 30, "dns": 20, "http": 20, "mtu": 10})
        # weight=30 → bonus_full = round(30 * 0.4) = 12，delay_full = 30 - 12 = 18
        assert health.score_wan(stat(30, 0), pol) == 18 + 12
        assert health.score_wan(stat(30, 2), pol) == 18 + 6
        assert health.score_wan(stat(30, 3), pol) == 18

    @pytest.mark.parametrize(
        ("loss", "bonus"),
        [(0.0, 10), (1.0, 5), (2.0, 5), (3.0, 0)],
    )
    def test_loss_bonus_tiers(self, loss: float, bonus: int) -> None:
        # 延迟 30ms 拿满 15 分
        assert health.score_wan(stat(30, loss), POLICY) == 15 + bonus

    def test_delay_bounds(self) -> None:
        # 150ms 延迟 0 分 + 无丢包奖励 10
        assert health.score_wan(stat(150, 0), POLICY) == 10
        assert health.score_wan(stat(None, 100), POLICY) == 0

    def test_warn_point_is_still_linear(self) -> None:
        # warn=100 只用于出结论；round(15 * 50 / 120) = 6，再加 10 分奖励
        assert health.score_wan(stat(100, 0), POLICY) == 16


# ===========================================================================
# DNS / HTTP：成功值的平均值线性计分
# ===========================================================================
class TestScoreDns:
    def test_no_successful_query_is_zero(self) -> None:
        assert health.score_dns([], POLICY) == 0
        assert health.score_dns([None, None], POLICY) == 0

    def test_bounds(self) -> None:
        assert health.score_dns([30.0], POLICY) == 20
        assert health.score_dns([200.0], POLICY) == 0
        assert health.score_dns([250.0], POLICY) == 0

    def test_average_skips_failed_servers(self) -> None:
        # 只统计成功项：(10+90)/2 = 50 → round(20 * 150 / 170) = round(17.65) = 18
        assert health.score_dns([10.0, None, 90.0], POLICY) == 18

    def test_warn_point_is_still_linear(self) -> None:
        # warn=100 只用于出结论；评分按 30→200 线性：
        # round(20 * 100 / 170) = round(11.76) = 12
        assert health.score_dns([100.0], POLICY) == 12


class TestScoreHttp:
    def test_bounds_and_none(self) -> None:
        assert health.score_http(149, POLICY) == 20
        assert health.score_http(150, POLICY) == 20
        assert health.score_http(1000, POLICY) == 0
        assert health.score_http(1000.1, POLICY) == 0
        assert health.score_http(None, POLICY) == 0

    def test_midpoint(self) -> None:
        # round(20 * 425 / 850) = 10
        assert health.score_http(575, POLICY) == 10

    def test_warn_threshold_is_not_a_scoring_knee(self) -> None:
        # warn 只用于出结论，评分仍按 good→poor 线性：
        # round(20 * 500 / 850) = round(11.76) = 12
        assert health.score_http(500, POLICY) == 12


# ===========================================================================
# MTU：四档 + 探测失败；verified 不影响分数
# ===========================================================================
class TestScoreMtu:
    @pytest.mark.parametrize(
        ("mtu", "expected"),
        [
            (1500, 10),
            (9000, 10),
            (1499, 8),
            (1492, 8),
            (1491, 5),
            (1400, 5),
            (1399, 0),
            (0, 0),
        ],
    )
    def test_bands(self, mtu: int, expected: int) -> None:
        assert health.score_mtu(MtuResult(mtu=mtu), POLICY) == expected

    def test_probe_failure_is_zero(self) -> None:
        assert health.score_mtu(MtuResult(), POLICY) == 0

    def test_verified_flag_does_not_change_score(self) -> None:
        assert health.score_mtu(MtuResult(mtu=1492, verified=True), POLICY) == 8
        assert health.score_mtu(MtuResult(mtu=1492, verified=False), POLICY) == 8

    def test_bands_use_policy(self) -> None:
        pol = Policy(mtu=MtuPolicy(standard=1400, pppoe=1380, low=1300))
        assert health.score_mtu(MtuResult(mtu=1400), pol) == 10
        assert health.score_mtu(MtuResult(mtu=1380), pol) == 8
        assert health.score_mtu(MtuResult(mtu=1300), pol) == 5
        assert health.score_mtu(MtuResult(mtu=1299), pol) == 0

    def test_bands_scale_with_weight(self) -> None:
        # 中间档同样按权重缩放：20 * 0.8 = 16，20 * 0.5 = 10
        pol = Policy(weights={"gateway": 15, "wan": 25, "dns": 20, "http": 20, "mtu": 20})
        assert health.score_mtu(MtuResult(mtu=1500), pol) == 20
        assert health.score_mtu(MtuResult(mtu=1492), pol) == 16
        assert health.score_mtu(MtuResult(mtu=1400), pol) == 10
        # 低权重时中间档也不会超过满分
        narrow = Policy(weights={"gateway": 15, "wan": 25, "dns": 20, "http": 20, "mtu": 5})
        assert health.score_mtu(MtuResult(mtu=1492), narrow) == 4
        assert health.score_mtu(MtuResult(mtu=1400), narrow) == 2


# ===========================================================================
# 权重归一化与评级
# ===========================================================================
class TestTotalAndGrade:
    def test_all_full_is_100(self) -> None:
        items = _items((15, 15), (25, 25), (20, 20), (20, 20), (10, 10))
        assert health.total_score(items) == 100

    def test_all_zero_is_0(self) -> None:
        items = _items((0, 15), (0, 25), (0, 20), (0, 20), (0, 10))
        assert health.total_score(items) == 0

    def test_empty_is_zero(self) -> None:
        assert health.total_score([]) == 0

    def test_normalization_matches_legacy_math(self) -> None:
        # 8+25+20+20+8 = 81；81/90*100 = 90
        items = _items((8, 15), (25, 25), (20, 20), (20, 20), (8, 10))
        assert health.total_score(items) == 90

    def test_dns_omitted_shrinks_the_denominator(self) -> None:
        # 没有 DNS 配置时权重和只剩 70：15+25+20+10 = 70 → 100
        items = _items((15, 15), (25, 25), (20, 20), (10, 10))
        assert health.total_score(items) == 100

    @pytest.mark.parametrize(
        ("total", "expected"),
        [
            (100, "优"),
            (85, "优"),
            (84, "良"),
            (70, "良"),
            (69, "中"),
            (50, "中"),
            (49, "差"),
            (0, "差"),
        ],
    )
    def test_grade_boundaries(self, total: int, expected: str) -> None:
        assert health.grade(total) == expected


# ===========================================================================
# Policy 驱动：阈值与权重都从 Policy 取
# ===========================================================================
class TestPolicyDriven:
    def test_gateway_band_from_policy(self) -> None:
        pol = Policy(gateway=Band(good=10, warn=40, poor=100))
        assert health.score_gateway(stat(10, 0), pol) == 15
        # round(15 * 40 / 90) = round(6.67) = 7
        assert health.score_gateway(stat(60, 0), pol) == 7
        assert health.score_gateway(stat(100, 0), pol) == 0

    def test_http_band_from_policy(self) -> None:
        pol = Policy(http_ttfb=Band(good=100, warn=300, poor=500))
        assert health.score_http(100, pol) == 20
        assert health.score_http(500, pol) == 0

    def test_weight_from_policy(self) -> None:
        pol = Policy(weights={"gateway": 30, "wan": 25, "dns": 20, "http": 20, "mtu": 10})
        assert health.score_gateway(stat(5, 0), pol) == 30
        # round(30 * 20 / 45) = round(13.33) = 13
        assert health.score_gateway(stat(30, 0), pol) == 13

    def test_missing_weight_falls_back_to_default(self) -> None:
        pol = Policy(weights={"gateway": 30})
        assert health.score_dns([30.0], pol) == 20
        assert health.score_http(150, pol) == 20


# ===========================================================================
# evaluate：整体评分 + Finding
# ===========================================================================
def _healthy(**overrides: object) -> tuple[Score, list[Finding]]:
    """全部正常的输入；用 overrides 替换单个维度。"""
    kwargs: dict[str, object] = {
        "gateway": stat(1.0, 0.0),
        "wan": stat(26.0, 0.0),
        "dns_latencies": [20.0],
        "dns_servers": ["223.5.5.5"],
        "http_ttfb": 30.0,
        "mtu": MtuResult(mtu=1500, payload=1472, verified=True),
    }
    kwargs.update(overrides)
    return health.evaluate(**kwargs)  # type: ignore[arg-type]


class TestEvaluate:
    def test_all_normal_is_full_marks_without_critical(self) -> None:
        score, findings = _healthy()
        assert score.total == 100
        assert score.grade == "优"
        assert len(score.items) == 5
        assert findings == []
        assert not [f for f in findings if f.severity is Severity.critical]

    def test_score_item_shape(self) -> None:
        score, _ = _healthy()
        assert score.items[0] == {
            "label": "网关",
            "score": 15,
            "weight": 15,
            "detail": "网关 1.0 ms / 丢包 0.0%",
        }
        assert [item["label"] for item in score.items] == ["网关", "外网", "DNS", "HTTP", "MTU"]

    def test_gateway_unreachable_is_critical(self) -> None:
        score, findings = _healthy(gateway=stat(None, 100.0))
        finding = _only(findings, FindingCode.GATEWAY_UNREACHABLE)
        assert finding.severity is Severity.critical
        assert "test" in finding.detail
        # 75/90*100 = 83.33 → 83
        assert score.total == 83

    def test_missing_gateway_is_also_unreachable(self) -> None:
        score, findings = _healthy(gateway=None)
        finding = _only(findings, FindingCode.GATEWAY_UNREACHABLE)
        assert finding.severity is Severity.critical
        assert "默认网关" in finding.detail
        assert score.total == 83

    def test_gateway_loss_warn_and_critical(self) -> None:
        _, warn_findings = _healthy(gateway=stat(20.0, 10.0))
        assert _only(warn_findings, FindingCode.GATEWAY_LOSS).severity is Severity.warn
        _, crit_findings = _healthy(gateway=stat(20.0, 60.0))
        assert _only(crit_findings, FindingCode.GATEWAY_LOSS).severity is Severity.critical

    def test_gateway_latency_high(self) -> None:
        _, findings = _healthy(gateway=stat(40.0, 0.0))
        assert _only(findings, FindingCode.GATEWAY_LATENCY_HIGH).severity is Severity.warn

    def test_gateway_unreachable_does_not_double_report(self) -> None:
        _, findings = _healthy(gateway=stat(None, 100.0))
        assert _codes(findings) == [FindingCode.GATEWAY_UNREACHABLE.value]

    def test_wan_unreachable_is_critical(self) -> None:
        _, findings = _healthy(wan=stat(None, 100.0))
        assert _only(findings, FindingCode.WAN_UNREACHABLE).severity is Severity.critical

    def test_wan_loss_and_latency(self) -> None:
        _, findings = _healthy(wan=stat(120.0, 5.0))
        assert _only(findings, FindingCode.WAN_LOSS).severity is Severity.warn
        assert _only(findings, FindingCode.WAN_LATENCY_HIGH).severity is Severity.warn

    def test_wan_major_loss_is_critical(self) -> None:
        _, findings = _healthy(wan=stat(20.0, 60.0))
        assert _only(findings, FindingCode.WAN_LOSS).severity is Severity.critical

    def test_dns_no_config_is_warn_and_not_scored(self) -> None:
        score, findings = _healthy(dns_servers=[], dns_latencies=[])
        assert _only(findings, FindingCode.DNS_NO_CONFIG).severity is Severity.warn
        assert "DNS" not in [item["label"] for item in score.items]
        # 其余四项 15+25+20+10 = 70，全满 → 100
        assert score.total == 100

    def test_dns_all_failed_is_critical(self) -> None:
        score, findings = _healthy(dns_servers=["192.0.2.1"], dns_latencies=[None, None])
        assert _only(findings, FindingCode.DNS_FAIL).severity is Severity.critical
        # 70/90*100 = 77.78 → 78
        assert score.total == 78

    def test_dns_slow_is_warn(self) -> None:
        _, findings = _healthy(dns_latencies=[150.0])
        assert _only(findings, FindingCode.DNS_SLOW).severity is Severity.warn

    def test_http_fail_is_critical(self) -> None:
        _, findings = _healthy(http_ttfb=None)
        assert _only(findings, FindingCode.HTTP_FAIL).severity is Severity.critical

    def test_http_slow_is_warn(self) -> None:
        _, findings = _healthy(http_ttfb=600.0)
        assert _only(findings, FindingCode.HTTP_SLOW).severity is Severity.warn

    @pytest.mark.parametrize(
        ("mtu", "verified", "code", "severity"),
        [
            (1492, True, FindingCode.MTU_PPPOE, Severity.info),
            (1450, True, FindingCode.MTU_LOW, Severity.warn),
            (1300, True, FindingCode.MTU_VERY_LOW, Severity.critical),
            (None, False, FindingCode.MTU_UNKNOWN, Severity.warn),
        ],
    )
    def test_mtu_findings(
        self, mtu: int | None, verified: bool, code: FindingCode, severity: Severity
    ) -> None:
        _, findings = _healthy(mtu=MtuResult(mtu=mtu, verified=verified))
        assert _only(findings, code).severity is severity

    def test_mtu_unverified_is_info(self) -> None:
        _, findings = _healthy(mtu=MtuResult(mtu=1492, verified=False))
        assert _only(findings, FindingCode.MTU_UNVERIFIED).severity is Severity.info
        # 1492 同时是 PPPoE，两条结论并存
        assert _codes(findings) == [
            FindingCode.MTU_PPPOE.value,
            FindingCode.MTU_UNVERIFIED.value,
        ]

    def test_standard_mtu_has_no_finding(self) -> None:
        _, findings = _healthy(mtu=MtuResult(mtu=1500, verified=True))
        assert findings == []

    def test_every_finding_has_actionable_advice(self) -> None:
        _, findings = health.evaluate(
            gateway=stat(None, 100.0),
            wan=stat(120.0, 5.0),
            dns_latencies=[150.0],
            dns_servers=["223.5.5.5"],
            http_ttfb=600.0,
            mtu=MtuResult(mtu=1492, verified=False),
        )
        assert len(findings) == 7
        valid_codes = {code.value for code in FindingCode}
        for finding in findings:
            assert finding.code in valid_codes
            assert finding.advice
            assert all(advice.strip() for advice in finding.advice)

    def test_explicit_default_policy_matches_none(self) -> None:
        kwargs = {
            "gateway": stat(1.0, 0.0),
            "wan": stat(26.0, 0.0),
            "dns_latencies": [20.0],
            "dns_servers": ["223.5.5.5"],
            "http_ttfb": 30.0,
            "mtu": MtuResult(mtu=1500, verified=True),
        }
        assert health.evaluate(**kwargs) == health.evaluate(**kwargs, policy=Policy.default())

    def test_custom_weights_still_reach_100(self) -> None:
        # 全部满格时，不管权重怎么配，归一化后都必须是 100，且不超满分
        weights = {"gateway": 15, "wan": 30, "dns": 20, "http": 20, "mtu": 20}
        pol = Policy(weights=weights)
        score, findings = health.evaluate(
            gateway=stat(1.0, 0.0),
            wan=stat(26.0, 0.0),
            dns_latencies=[20.0],
            dns_servers=["223.5.5.5"],
            http_ttfb=30.0,
            mtu=MtuResult(mtu=1500, verified=True),
            policy=pol,
        )
        assert score.total == 100
        assert findings == []
        for item in score.items:
            assert item["score"] <= item["weight"]


# ===========================================================================
# 纯函数性质
# ===========================================================================
class TestPurity:
    def test_evaluate_is_deterministic_and_silent(self, capsys: pytest.CaptureFixture[str]) -> None:
        kwargs = {
            "gateway": stat(None, 100.0),
            "wan": stat(120.0, 5.0),
            "dns_latencies": [150.0],
            "dns_servers": ["223.5.5.5"],
            "http_ttfb": 600.0,
            "mtu": MtuResult(mtu=1492, verified=False),
        }
        assert health.evaluate(**kwargs) == health.evaluate(**kwargs)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_module_has_no_io_dependencies(self) -> None:
        source = inspect.getsource(health)
        for banned in ("import subprocess", "import socket", "httpx", "open(", "print("):
            assert banned not in source


_LATENCY = st.floats(min_value=0, max_value=5000, allow_nan=False, allow_infinity=False)


class TestMonotonicity:
    @given(a=_LATENCY, b=_LATENCY)
    def test_gateway_latency_never_increases_score(self, a: float, b: float) -> None:
        low, high = min(a, b), max(a, b)
        for loss in (0.0, 1.9, 10.0, 49.9, 50.0, 100.0):
            assert health.score_gateway(stat(low, loss), POLICY) >= health.score_gateway(
                stat(high, loss), POLICY
            )

    @given(a=_LATENCY, b=_LATENCY)
    def test_wan_latency_never_increases_score(self, a: float, b: float) -> None:
        low, high = min(a, b), max(a, b)
        for loss in (0.0, 1.5, 5.0, 100.0):
            assert health.score_wan(stat(low, loss), POLICY) >= health.score_wan(
                stat(high, loss), POLICY
            )

    @given(a=_LATENCY, b=_LATENCY)
    def test_dns_latency_never_increases_score(self, a: float, b: float) -> None:
        low, high = min(a, b), max(a, b)
        assert health.score_dns([low], POLICY) >= health.score_dns([high], POLICY)

    @given(a=_LATENCY, b=_LATENCY)
    def test_http_latency_never_increases_score(self, a: float, b: float) -> None:
        low, high = min(a, b), max(a, b)
        assert health.score_http(low, POLICY) >= health.score_http(high, POLICY)

    @given(
        a=st.floats(min_value=0, max_value=100, allow_nan=False, allow_infinity=False),
        b=st.floats(min_value=0, max_value=100, allow_nan=False, allow_infinity=False),
    )
    def test_gateway_loss_never_increases_score(self, a: float, b: float) -> None:
        low, high = min(a, b), max(a, b)
        assert health.score_gateway(stat(5.0, low), POLICY) >= health.score_gateway(
            stat(5.0, high), POLICY
        )

    @given(a=st.integers(min_value=0, max_value=9000), b=st.integers(min_value=0, max_value=9000))
    def test_mtu_score_never_decreases_with_size(self, a: int, b: int) -> None:
        low, high = min(a, b), max(a, b)
        assert health.score_mtu(MtuResult(mtu=low), POLICY) <= health.score_mtu(
            MtuResult(mtu=high), POLICY
        )
