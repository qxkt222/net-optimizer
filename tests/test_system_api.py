# -*- coding: utf-8 -*-
"""SystemApi / FakeSystemApi 契约与领域模型冻结性测试。

不联网、不调真实系统 API：这里只测「接口返回什么」与「模型能不能被改」。
"""

from __future__ import annotations

import dataclasses
from dataclasses import FrozenInstanceError

import pytest

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
from netopt.system import FakeSystemApi, SystemApi, SystemUnavailable


def _adapter() -> Adapter:
    return Adapter(
        index=7,
        guid="{4F1A2B3C-1111-2222-3333-444455556666}",
        name="以太网",
        description="Intel(R) Ethernet Connection",
        mac="AA-BB-CC-DD-EE-FF",
        mtu=1500,
        connected=True,
        kind="ethernet",
        speed_bps=1_000_000_000,
    )


def test_fake_returns_constructed_data() -> None:
    adapter = _adapter()
    address = Address(adapter_index=7, family=2, address="192.0.2.10", prefix_len=24)
    dns = InterfaceDns(
        adapter_index=7,
        interface_name="以太网",
        servers=["223.5.5.5", "2400:3200::1"],
        source="static",
    )
    route = Route(
        destination="0.0.0.0",
        prefix_len=0,
        next_hop="192.0.2.1",
        interface_index=7,
        metric=25,
        is_default=True,
    )
    stats = InterfaceStats(index=7, name="以太网", in_octets=123, out_octets=456)
    platform = PlatformInfo(os_build="22631", windows_version="11", is_admin=True)
    wifi = WifiState(connected=True, ssid="home", signal_pct=80)
    scan = WifiScan(networks=[WifiNetwork(ssid="home", channel=36)])

    fake = FakeSystemApi(
        platform_info=platform,
        adapters=[adapter],
        addresses=[address],
        dns_servers=[dns],
        routes=[route],
        if_stats=[stats],
        wifi=wifi,
        wifi_scan=scan,
    )

    assert fake.platform_info() == platform
    assert fake.adapters() == [adapter]
    assert fake.addresses() == [address]
    assert fake.dns_servers() == [dns]
    assert fake.routes() == [route]
    assert fake.if_stats() == [stats]
    assert fake.wifi() == wifi
    assert fake.wifi_scan() == scan


def test_fake_defaults_are_empty() -> None:
    fake = FakeSystemApi()

    assert fake.platform_info() == PlatformInfo()
    assert fake.adapters() == []
    assert fake.addresses() == []
    assert fake.dns_servers() == []
    assert fake.routes() == []
    assert fake.if_stats() == []
    assert fake.wifi() == WifiState()
    assert fake.wifi_scan() == WifiScan()


def test_fake_satisfies_protocol() -> None:
    assert isinstance(FakeSystemApi(), SystemApi)


def test_fake_returns_copies_not_internal_state() -> None:
    dns = InterfaceDns(
        adapter_index=1, interface_name="以太网", servers=["8.8.8.8"], source="static"
    )
    fake = FakeSystemApi(adapters=[_adapter()], dns_servers=[dns])

    first = fake.adapters()
    first.clear()
    assert fake.adapters() == [_adapter()]

    first_dns = fake.dns_servers()
    first_dns[0].servers.append("1.1.1.1")
    assert fake.dns_servers()[0].servers == ["8.8.8.8"]


def test_system_unavailable_is_catchable_and_has_message() -> None:
    with pytest.raises(SystemUnavailable) as excinfo:
        raise SystemUnavailable("wlanapi.dll 不可用，无法读取 WiFi 状态")

    assert str(excinfo.value).strip()
    assert isinstance(excinfo.value, RuntimeError)


@pytest.mark.parametrize(
    "model",
    [
        PlatformInfo(),
        _adapter(),
        Address(adapter_index=1, family=2, address="192.0.2.1"),
        InterfaceDns(adapter_index=1, interface_name="以太网"),
        Route(
            destination="0.0.0.0",
            prefix_len=0,
            next_hop="192.0.2.1",
            interface_index=1,
            metric=25,
        ),
        InterfaceStats(index=1, name="以太网"),
        WifiState(),
        WifiNetwork(),
        WifiScan(),
    ],
    ids=[
        "platform-info",
        "adapter",
        "address",
        "interface-dns",
        "route",
        "interface-stats",
        "wifi-state",
        "wifi-network",
        "wifi-scan",
    ],
)
def test_models_are_frozen(model: object) -> None:
    field_name = dataclasses.fields(model)[0].name  # type: ignore[arg-type]

    with pytest.raises(FrozenInstanceError):
        setattr(model, field_name, None)


def test_interface_dns_default_servers_are_not_shared() -> None:
    first = InterfaceDns(adapter_index=1, interface_name="以太网")
    second = InterfaceDns(adapter_index=2, interface_name="WLAN")

    first.servers.append("8.8.8.8")

    assert first.servers == ["8.8.8.8"]
    assert second.servers == []


def test_wifi_scan_default_networks_are_not_shared() -> None:
    first = WifiScan()
    second = WifiScan()

    first.networks.append(WifiNetwork(ssid="home"))

    assert len(first.networks) == 1
    assert second.networks == []
