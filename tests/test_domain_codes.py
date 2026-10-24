# -*- coding: utf-8 -*-
"""常量码表测试：唯一性、关键码存在、StrEnum 语义。"""

from __future__ import annotations

from enum import StrEnum

import pytest

from netopt.domain.codes import FindingCode, ProbeErrorCode


@pytest.mark.parametrize("enum_cls", [FindingCode, ProbeErrorCode])
def test_codes_are_unique(enum_cls: type[StrEnum]) -> None:
    # 用 __members__ 而不是迭代：迭代会把重复值折叠成别名，漏掉重复。
    values = [member.value for member in enum_cls.__members__.values()]
    names = list(enum_cls.__members__)

    assert len(values) == len(set(values))
    assert len(names) == len(set(names))
    assert issubclass(enum_cls, str)


def test_key_finding_codes_exist() -> None:
    expected = {
        "GATEWAY_UNREACHABLE",
        "GATEWAY_LOSS",
        "GATEWAY_LATENCY_HIGH",
        "WAN_UNREACHABLE",
        "WAN_LOSS",
        "WAN_LATENCY_HIGH",
        "DNS_NO_CONFIG",
        "DNS_IPV6_ONLY",
        "DNS_FAIL",
        "DNS_SLOW",
        "HTTP_FAIL",
        "HTTP_SLOW",
        "MTU_PPPOE",
        "MTU_LOW",
        "MTU_VERY_LOW",
        "MTU_UNKNOWN",
        "MTU_UNVERIFIED",
        "WIFI_DISCONNECTED",
        "WIFI_SIGNAL_WEAK",
        "WIFI_LOCATION_DENIED",
        "SYSTEM_UNAVAILABLE",
        "PERMISSION_DENIED",
    }
    assert expected <= set(FindingCode.__members__)


def test_key_probe_error_codes_exist() -> None:
    expected = {"TIMEOUT", "DENIED", "MISSING", "UNAVAILABLE", "PARSE", "NETWORK"}
    assert expected <= set(ProbeErrorCode.__members__)
    assert ProbeErrorCode.TIMEOUT == "timeout"
    assert ProbeErrorCode.NETWORK.value == "network"


def test_finding_code_is_usable_as_plain_string() -> None:
    assert FindingCode.GATEWAY_UNREACHABLE == "GATEWAY_UNREACHABLE"
    assert isinstance(FindingCode.WAN_LOSS, str)
