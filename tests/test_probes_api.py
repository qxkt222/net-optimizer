# -*- coding: utf-8 -*-
"""v2 探测上下文与 SystemApi 读探测的测试。

**安全底线**：这里只用 :class:`FakeSystemApi` 与内存数据，绝不读取本机网络状态、
不执行任何系统命令。重点覆盖缺陷 D11：默认路由落在 VPN / 虚拟网卡时，
``primary_adapters_from_api`` 必须返回空列表，而不是把它们当成本地主接口。
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from netopt import probes
from netopt.domain.codes import ProbeErrorCode
from netopt.domain.models import Adapter, InterfaceDns, Route
from netopt.system import FakeSystemApi


def _adapter(
    index: int,
    name: str,
    *,
    connected: bool = True,
    is_primary: bool = True,
    kind: str = "ethernet",
) -> Adapter:
    """造一块最小可用的适配器。"""
    return Adapter(
        index=index,
        guid=f"{{{index:08X}-0000-0000-0000-000000000000}}",
        name=name,
        description=name,
        mac=None,
        mtu=1500,
        connected=connected,
        kind=kind,
        is_primary=is_primary,
    )


def _default_route(interface_index: int, metric: int, next_hop: str = "192.0.2.1") -> Route:
    """造一条 IPv4 默认路由。"""
    return Route(
        destination="0.0.0.0",
        prefix_len=0,
        next_hop=next_hop,
        interface_index=interface_index,
        metric=metric,
        is_default=True,
    )


# ===========================================================================
# ProbeContext
# ===========================================================================
def test_with_budget_starts_with_full_budget() -> None:
    ctx = probes.ProbeContext.with_budget(20.0)

    assert ctx.remaining() > 19.0
    assert ctx.expired() is False
    assert ctx.cancelled() is False
    assert ctx.errors == []


def test_budget_exhausted_immediately() -> None:
    ctx = probes.ProbeContext.with_budget(0.0)

    assert ctx.remaining() == 0.0
    assert ctx.expired() is True


def test_remaining_never_negative() -> None:
    """负预算也不能让 remaining() 变成负数。"""
    ctx = probes.ProbeContext.with_budget(-5.0)

    assert ctx.remaining() == 0.0
    assert ctx.expired() is True


def test_cancel_takes_effect() -> None:
    ctx = probes.ProbeContext.with_budget(10.0)
    assert ctx.cancelled() is False

    ctx.cancel.set()

    assert ctx.cancelled() is True


def test_timeout_for_is_clamped_by_remaining() -> None:
    ctx = probes.ProbeContext.with_budget(2.0)

    assert ctx.timeout_for(1.0) == pytest.approx(1.0)
    assert 0.0 <= ctx.timeout_for(100.0) <= 2.0


def test_record_error_uses_constants_and_retryable() -> None:
    ctx = probes.ProbeContext.with_budget(5.0)

    ctx.record_error(ProbeErrorCode.TIMEOUT, "ping", "等待回复超时", retryable=True)

    assert len(ctx.errors) == 1
    err = ctx.errors[0]
    assert err.code == "timeout"
    assert err.source == "ping"
    assert err.message == "等待回复超时"
    assert err.retryable is True


def test_record_error_is_thread_safe() -> None:
    """并发写 50 条错误，一条都不能丢。"""
    ctx = probes.ProbeContext.with_budget(5.0)
    barrier = threading.Barrier(10)

    def worker(batch: int) -> None:
        barrier.wait()
        for i in range(5):
            ctx.record_error(
                ProbeErrorCode.NETWORK,
                "worker",
                f"{batch}-{i}",
            )

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(worker, range(10)))

    assert len(ctx.errors) == 50
    assert {err.code for err in ctx.errors} == {"network"}
    assert len({err.message for err in ctx.errors}) == 50


# ===========================================================================
# adapters_from_api
# ===========================================================================
def test_adapters_from_api_returns_everything_unfiltered() -> None:
    ethernet = _adapter(7, "以太网")
    vpn = _adapter(11, "Radmin VPN", is_primary=False, kind="vpn")
    loopback = _adapter(1, "Loopback Pseudo-Interface 1", is_primary=False, kind="loopback")
    api = FakeSystemApi(adapters=[ethernet, vpn, loopback])

    assert probes.adapters_from_api(api) == [ethernet, vpn, loopback]


# ===========================================================================
# primary_adapters_from_api（D11）
# ===========================================================================
def test_primary_adapter_on_ethernet() -> None:
    ethernet = _adapter(7, "以太网")
    api = FakeSystemApi(adapters=[ethernet], routes=[_default_route(7, 25)])

    assert probes.primary_adapters_from_api(api) == [ethernet]


def test_default_route_on_radmin_vpn_returns_empty() -> None:
    """VPN 即使持有默认路由，也不能被当成本地主接口。"""
    ethernet = _adapter(7, "以太网", connected=False)
    vpn = _adapter(11, "Radmin VPN", is_primary=False, kind="vpn")
    api = FakeSystemApi(adapters=[ethernet, vpn], routes=[_default_route(11, 5)])

    assert probes.primary_adapters_from_api(api) == []


def test_default_route_on_vethernet_returns_empty() -> None:
    """Hyper-V 虚拟交换机持有默认路由时同样要排除。"""
    ethernet = _adapter(7, "以太网", connected=False)
    vethernet = _adapter(15, "vEthernet (Default Switch)", is_primary=False, kind="virtual")
    api = FakeSystemApi(adapters=[ethernet, vethernet], routes=[_default_route(15, 5)])

    assert probes.primary_adapters_from_api(api) == []


def test_multiple_default_routes_use_smallest_metric() -> None:
    wlan = _adapter(5, "WLAN", kind="wlan")
    ethernet = _adapter(7, "以太网")
    api = FakeSystemApi(
        adapters=[wlan, ethernet],
        routes=[_default_route(5, 50), _default_route(7, 25)],
    )

    assert probes.primary_adapters_from_api(api) == [ethernet]


def test_primary_adapter_requires_connected() -> None:
    ethernet = _adapter(7, "以太网", connected=False)
    api = FakeSystemApi(adapters=[ethernet], routes=[_default_route(7, 25)])

    assert probes.primary_adapters_from_api(api) == []


def test_primary_adapter_without_default_route_is_empty() -> None:
    ethernet = _adapter(7, "以太网")
    api = FakeSystemApi(adapters=[ethernet], routes=[])

    assert probes.primary_adapters_from_api(api) == []


# ===========================================================================
# gateway_from_api
# ===========================================================================
def test_gateway_none_without_routes() -> None:
    assert probes.gateway_from_api(FakeSystemApi()) is None


def test_gateway_ignores_non_default_routes() -> None:
    route = Route(
        destination="192.0.2.0",
        prefix_len=24,
        next_hop="192.0.2.1",
        interface_index=7,
        metric=1,
        is_default=False,
    )

    assert probes.gateway_from_api(FakeSystemApi(routes=[route])) is None


def test_gateway_picks_route_with_smallest_metric() -> None:
    slow = _default_route(5, 50)
    fast = _default_route(7, 25)
    api = FakeSystemApi(routes=[slow, fast])

    assert probes.gateway_from_api(api) == fast


# ===========================================================================
# dns_from_api
# ===========================================================================
def test_dns_from_api_returns_configs_unchanged() -> None:
    configs = [
        InterfaceDns(
            adapter_index=7,
            interface_name="以太网",
            servers=["223.5.5.5", "2400:3200::1"],
            source="static",
        ),
        InterfaceDns(adapter_index=11, interface_name="Radmin VPN", servers=[], source="none"),
    ]
    api = FakeSystemApi(dns_servers=configs)

    result = probes.dns_from_api(api)

    assert result == configs
    assert [item.interface_name for item in result] == ["以太网", "Radmin VPN"]
