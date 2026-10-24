# -*- coding: utf-8 -*-
"""Policy 测试：默认值与 v1 对齐、非法配置拒绝、分档边界。"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from netopt.domain.policy import DEFAULT_WEIGHTS, Band, LossPolicy, MtuPolicy, Policy
from netopt.domain.report import Severity


def test_default_bands_match_v1_numbers() -> None:
    policy = Policy.default()

    assert (policy.gateway.good, policy.gateway.warn, policy.gateway.poor) == (5, 30, 50)
    assert (policy.wan.good, policy.wan.warn, policy.wan.poor) == (30, 100, 150)
    assert (policy.dns.good, policy.dns.warn, policy.dns.poor) == (30, 100, 200)
    assert (policy.http_ttfb.good, policy.http_ttfb.warn, policy.http_ttfb.poor) == (
        150,
        500,
        1000,
    )
    assert (policy.loss.tolerate, policy.loss.unusable) == (2, 50)
    assert (policy.mtu.standard, policy.mtu.pppoe, policy.mtu.low) == (1500, 1492, 1400)


def test_policy_default_equals_constructor() -> None:
    assert Policy.default() == Policy()


def test_weights_match_v1_and_sum_to_90() -> None:
    policy = Policy.default()

    assert policy.weights == {
        "gateway": 15,
        "wan": 25,
        "dns": 20,
        "http": 20,
        "mtu": 10,
    }
    assert sum(policy.weights.values()) == 90
    assert policy.weights == DEFAULT_WEIGHTS


def test_weights_are_not_shared_between_instances() -> None:
    first = Policy()
    second = Policy()
    first.weights["extra"] = 1
    assert "extra" not in second.weights


@pytest.mark.parametrize(
    "good, warn, poor",
    [
        (30, 10, 50),  # good > warn
        (5, 50, 30),  # warn > poor
        (-1, 10, 50),  # 出现负阈值
        (0, 0, 10),  # good == warn
        (5, 5, 10),  # good == warn
        (5, 10, 10),  # warn == poor
    ],
)
def test_invalid_band_order_rejected(good: float, warn: float, poor: float) -> None:
    with pytest.raises(ValidationError):
        Band(good=good, warn=warn, poor=poor)


def test_invalid_loss_policy_rejected() -> None:
    with pytest.raises(ValidationError):
        LossPolicy(tolerate=50, unusable=2)
    with pytest.raises(ValidationError):
        LossPolicy(tolerate=-1, unusable=50)


def test_invalid_mtu_policy_rejected() -> None:
    with pytest.raises(ValidationError):
        MtuPolicy(standard=1500, pppoe=1500, low=1400)
    with pytest.raises(ValidationError):
        MtuPolicy(standard=1500, pppoe=1400, low=1400)


@pytest.mark.parametrize("weights", [{}, {"gateway": 0}, {"gateway": -1, "wan": 25}])
def test_non_positive_weights_rejected(weights: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        Policy(weights=weights)


def test_classify_boundaries() -> None:
    band = Band(good=5, warn=30, poor=50)

    assert band.classify(None) is Severity.warn
    assert band.classify(5) is Severity.ok
    assert band.classify(5.1) is Severity.info
    assert band.classify(30) is Severity.info
    assert band.classify(30.1) is Severity.warn
    assert band.classify(50) is Severity.warn
    assert band.classify(50.1) is Severity.critical


def test_classify_nan_is_warn() -> None:
    band = Band(good=5, warn=30, poor=50)
    assert band.classify(float("nan")) is Severity.warn


def test_default_policy_classification_is_consistent_across_commands() -> None:
    """同一次 120 ms 外网测量，任何消费方都得到同一档位。"""
    policy = Policy.default()

    assert policy.wan.classify(120) is Severity.warn
    assert policy.dns.classify(120) is Severity.warn
    assert policy.http_ttfb.classify(120) is Severity.ok
