# -*- coding: utf-8 -*-
"""Finding / ProbeError 的机器可读常量表。

两套常量都使用 :class:`enum.StrEnum`（3.11+），成员可直接当字符串用，
但比较与赋值必须走常量，禁止在代码里散落字面量。

取值约定：

- :class:`ProbeErrorCode` 的值受 SPEC §5.1 注释约束，为小写单词。
- :class:`FindingCode` 尚无既定取值，统一取与成员名相同的大写形式，
  避免出现“同一条码两种拼写”。
"""

from __future__ import annotations

from enum import StrEnum


class FindingCode(StrEnum):
    """诊断结论码。``Finding.code`` 取这里的值，建议文案按它分发。"""

    # 网关
    GATEWAY_UNREACHABLE = "GATEWAY_UNREACHABLE"
    GATEWAY_LOSS = "GATEWAY_LOSS"
    GATEWAY_LATENCY_HIGH = "GATEWAY_LATENCY_HIGH"

    # 外网
    WAN_UNREACHABLE = "WAN_UNREACHABLE"
    WAN_LOSS = "WAN_LOSS"
    WAN_LATENCY_HIGH = "WAN_LATENCY_HIGH"

    # DNS
    DNS_NO_CONFIG = "DNS_NO_CONFIG"
    DNS_IPV6_ONLY = "DNS_IPV6_ONLY"
    DNS_FAIL = "DNS_FAIL"
    DNS_SLOW = "DNS_SLOW"

    # HTTP
    HTTP_FAIL = "HTTP_FAIL"
    HTTP_SLOW = "HTTP_SLOW"

    # MTU
    MTU_PPPOE = "MTU_PPPOE"
    MTU_LOW = "MTU_LOW"
    MTU_VERY_LOW = "MTU_VERY_LOW"
    MTU_UNKNOWN = "MTU_UNKNOWN"
    MTU_UNVERIFIED = "MTU_UNVERIFIED"

    # WiFi
    WIFI_DISCONNECTED = "WIFI_DISCONNECTED"
    WIFI_SIGNAL_WEAK = "WIFI_SIGNAL_WEAK"
    WIFI_LOCATION_DENIED = "WIFI_LOCATION_DENIED"

    # 系统
    SYSTEM_UNAVAILABLE = "SYSTEM_UNAVAILABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"

    # 归因链（analysis/diagnose.py）：按「问题出在哪一段」区分，而不是按症状。
    DIAG_LOCAL_LINK = "DIAG_LOCAL_LINK"
    DIAG_ACCESS_NETWORK = "DIAG_ACCESS_NETWORK"
    DIAG_ISP_BACKBONE = "DIAG_ISP_BACKBONE"
    DIAG_DNS = "DIAG_DNS"
    DIAG_APP_LAYER = "DIAG_APP_LAYER"
    DIAG_TCP_RETRANSMIT = "DIAG_TCP_RETRANSMIT"


class ProbeErrorCode(StrEnum):
    """探测失败码。``ProbeError.code`` 取这里的值。"""

    TIMEOUT = "timeout"
    DENIED = "denied"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"
    PARSE = "parse"
    NETWORK = "network"


__all__ = ["FindingCode", "ProbeErrorCode"]
