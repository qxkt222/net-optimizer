# -*- coding: utf-8 -*-
"""``LiveSystemApi`` 纯委托测试。

不碰真实 DLL、不读注册表：本文件把 ``netopt.system.iphlpapi`` /
``netopt.system.wlanapi`` 的模块函数替换成哨兵，验证 8 个协议方法逐一
委托并把返回值原样交回。另外用哨兵版 ``ctypes.WinDLL`` 证明
``import netopt.system.live`` 不会在 import 阶段加载任何 DLL。
"""

from __future__ import annotations

import ctypes
import importlib
import sys
from collections.abc import Callable
from typing import Any

import pytest

import netopt.system.iphlpapi as iphlpapi
import netopt.system.wlanapi as wlanapi
from netopt.domain.models import (
    Adapter,
    Address,
    InterfaceDns,
    InterfaceStats,
    PlatformInfo,
    Route,
    WifiScan,
    WifiState,
)
from netopt.system import LiveSystemApi, SystemApi

#: 每个用例的期望返回值；用 ``is`` 断言「原样返回」，因此必须是同一对象。
_DELEGATIONS: list[tuple[str, Any, str, object]] = [
    ("platform_info", iphlpapi, "platform_info", PlatformInfo(os_build="22631")),
    (
        "adapters",
        iphlpapi,
        "adapters",
        [
            Adapter(
                index=1,
                guid=None,
                name="以太网",
                description="",
                mac=None,
                mtu=1500,
                connected=True,
            )
        ],
    ),
    ("addresses", iphlpapi, "addresses", [Address(adapter_index=1, family=2, address="10.0.0.2")]),
    (
        "dns_servers",
        iphlpapi,
        "dns_servers",
        [InterfaceDns(adapter_index=1, interface_name="以太网", servers=["223.5.5.5"])],
    ),
    (
        "routes",
        iphlpapi,
        "routes",
        [
            Route(
                destination="0.0.0.0",
                prefix_len=0,
                next_hop=None,
                interface_index=1,
                metric=25,
            )
        ],
    ),
    ("if_stats", iphlpapi, "if_stats", [InterfaceStats(index=1, name="以太网", in_octets=1)]),
    ("wifi", wlanapi, "wifi_state", WifiState(connected=True, ssid="home")),
    ("wifi_scan", wlanapi, "wifi_scan", WifiScan(networks=[])),
]


@pytest.mark.parametrize(
    ("method", "module", "func_name", "value"),
    _DELEGATIONS,
    ids=[case[0] for case in _DELEGATIONS],
)
def test_method_delegates_to_module_function(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    module: Any,
    func_name: str,
    value: object,
) -> None:
    """协议方法应无参调用对应模块函数，并原样返回其结果。"""
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def fake(*args: Any, **kwargs: Any) -> object:
        calls.append((args, kwargs))
        return value

    monkeypatch.setattr(module, func_name, fake)

    result = getattr(LiveSystemApi(), method)()

    assert result is value
    assert calls == [((), {})]


def test_live_satisfies_protocol() -> None:
    """``LiveSystemApi`` 满足 ``SystemApi`` 协议（只是 isinstance 检查，不读系统）。"""
    assert isinstance(LiveSystemApi(), SystemApi)


def test_import_live_does_not_load_dll(monkeypatch: pytest.MonkeyPatch) -> None:
    """import ``netopt.system.live`` 不得加载 DLL：用哨兵替换 ``ctypes.WinDLL``。"""
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def sentinel_win_dll(*args: Any, **kwargs: Any) -> Callable[..., Any]:
        calls.append((args, kwargs))
        raise AssertionError("import netopt.system.live 不应加载 DLL")

    monkeypatch.setattr(ctypes, "WinDLL", sentinel_win_dll)
    monkeypatch.delitem(sys.modules, "netopt.system.live", raising=False)

    module = importlib.import_module("netopt.system.live")

    assert module.LiveSystemApi is not None
    assert calls == []
