# -*- coding: utf-8 -*-
"""iphlpapi 读路径测试：纯函数、结构体解析与真机只读验证。

真机测试只调用读 API（``GetAdaptersAddresses`` / ``GetIpForwardTable2`` /
``GetIfTable2``），绝不写系统；非 Windows 平台直接 skip。
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys

import pytest

from netopt.domain.models import Adapter, Route
from netopt.system import iphlpapi

#: 合成缓冲区测试用到的 ``MIB_IF_ROW2`` 字段偏移（Windows SDK x64 布局）。
_IF_INDEX_OFFSET = 8
_IF_ALIAS_OFFSET = 28
_IF_RECEIVE_SPEED_OFFSET = 1200
_IF_IN_OCTETS_OFFSET = 1208
_IF_IN_DISCARDS_OFFSET = 1232
_IF_IN_ERRORS_OFFSET = 1240
_IF_OUT_OCTETS_OFFSET = 1280
_IF_OUT_DISCARDS_OFFSET = 1304
_IF_OUT_ERRORS_OFFSET = 1312

_live_only = pytest.mark.skipif(sys.platform != "win32", reason="iphlpapi 仅存在于 Windows")


def _sockaddr_buffer(family: int, packed: bytes) -> ctypes.Array[ctypes.c_char]:
    """构造一个 IPv4 / IPv6 ``SOCKADDR`` 缓冲区。"""
    if family == socket.AF_INET:
        raw = bytearray(16)
        raw[4:8] = packed
    else:
        raw = bytearray(28)
        raw[8:24] = packed
    struct.pack_into("<H", raw, 0, family)
    return ctypes.create_string_buffer(bytes(raw), len(raw))


def _route(destination: str, metric: int, *, is_default: bool = True) -> Route:
    """构造一条用于测试默认路由选择的记录。"""
    return Route(
        destination=destination,
        prefix_len=0 if is_default else 24,
        next_hop="192.0.2.1",
        interface_index=2,
        metric=metric,
        is_default=is_default,
    )


# ---------------------------------------------------------------------------
# 纯函数
# ---------------------------------------------------------------------------


def test_sockaddr_to_str_ipv4() -> None:
    buffer = _sockaddr_buffer(socket.AF_INET, socket.inet_aton("192.0.2.4"))
    pointer = ctypes.addressof(buffer)
    assert iphlpapi._sockaddr_to_str(pointer) == "192.0.2.4"
    assert iphlpapi._sockaddr_to_str(pointer, socket.AF_INET) == "192.0.2.4"


def test_sockaddr_to_str_ipv6() -> None:
    packed = socket.inet_pton(socket.AF_INET6, "2409:8a5c::1")
    buffer = _sockaddr_buffer(socket.AF_INET6, packed)
    assert iphlpapi._sockaddr_to_str(ctypes.addressof(buffer)) == "2409:8a5c::1"


def test_sockaddr_to_str_none_and_unknown_family() -> None:
    buffer = _sockaddr_buffer(socket.AF_INET, socket.inet_aton("127.0.0.1"))
    pointer = ctypes.addressof(buffer)
    assert iphlpapi._sockaddr_to_str(None) is None
    assert iphlpapi._sockaddr_to_str(pointer, 9999) is None


@pytest.mark.parametrize(
    ("mask", "expected"),
    [
        ("0.0.0.0", 0),
        ("255.0.0.0", 8),
        ("255.255.255.0", 24),
        ("255.255.240.0", 20),
        ("255.255.255.255", 32),
    ],
)
def test_mask_to_prefix(mask: str, expected: int) -> None:
    assert iphlpapi._mask_to_prefix(mask) == expected


@pytest.mark.parametrize("mask", ["", "255.255.0", "255.0.255.0", "256.0.0.0", "abc.0.0.0"])
def test_mask_to_prefix_rejects_invalid(mask: str) -> None:
    with pytest.raises(ValueError):
        iphlpapi._mask_to_prefix(mask)


def test_decode_wchar_stops_at_nul() -> None:
    buffer = (ctypes.c_wchar * 8)()
    buffer[0] = "以"
    buffer[1] = "太"
    buffer[2] = "网"
    assert iphlpapi._decode_wchar(buffer) == "以太网"


def test_decode_wchar_handles_empty_and_fully_filled() -> None:
    assert iphlpapi._decode_wchar((ctypes.c_wchar * 4)()) == ""
    filled = (ctypes.c_wchar * 4)("W", "L", "A", "N")
    assert iphlpapi._decode_wchar(filled) == "WLAN"


def test_mac_to_str() -> None:
    assert iphlpapi._mac_to_str(b"\x02\x00\x00\x00\x00\x01") == "02:00:00:00:00:01"
    assert iphlpapi._mac_to_str(b"") is None
    assert iphlpapi._mac_to_str(None) is None


@pytest.mark.parametrize(
    ("name", "if_type", "tunnel_type", "expected"),
    [
        ("Loopback Pseudo-Interface 1", 6, 0, ("loopback", False)),
        ("环回接口", 6, 0, ("loopback", False)),
        ("vEthernet (Default Switch)", 6, 0, ("virtual", False)),
        ("Hyper-V Virtual Ethernet Adapter", 6, 0, ("virtual", False)),
        ("WSL", 0, 0, ("virtual", False)),
        # VPN 默认不参与 DNS 修改（D11：不打断 split-DNS），is_primary=False。
        ("Radmin VPN", 6, 0, ("vpn", False)),
        ("WireGuard Tunnel", 6, 0, ("vpn", False)),
        # 隧道 / 伪接口不是实体网卡，也不能当主接口。
        ("Teredo Tunneling Pseudo-Interface", 131, 0, ("vpn", False)),
        ("Teredo Tunneling Pseudo-Interface", 6, 0, ("vpn", False)),
        ("ISATAP", 6, 0, ("vpn", False)),
        ("6to4 Adapter", 6, 0, ("vpn", False)),
        ("Local Area Connection* 1 Tunnel Adapter", 6, 0, ("vpn", False)),
        ("WLAN", 71, 0, ("wlan", True)),
        ("以太网", 6, 0, ("ethernet", True)),
        ("蓝牙网络连接", 6, 0, ("ethernet", True)),
        ("未知接口", 0, 0, ("unknown", True)),
    ],
)
def test_classify(name: str, if_type: int, tunnel_type: int, expected: tuple[str, bool]) -> None:
    assert iphlpapi._classify(name, if_type, tunnel_type) == expected


def test_pick_default_uses_smallest_metric() -> None:
    routes = [
        _route("0.0.0.0", 100),
        _route("0.0.0.0", 26),
        _route("::", 256),
        _route("192.0.2.0", 1, is_default=False),
    ]
    chosen = iphlpapi._pick_default(routes)
    assert chosen is not None
    assert chosen.metric == 26
    assert chosen.destination == "0.0.0.0"


def test_pick_default_can_choose_ipv6() -> None:
    routes = [_route("0.0.0.0", 100), _route("::", 25)]
    chosen = iphlpapi._pick_default(routes)
    assert chosen is not None
    assert chosen.destination == "::"


def test_pick_default_prefers_ipv4_on_tie() -> None:
    routes = [_route("::", 30), _route("0.0.0.0", 30)]
    chosen = iphlpapi._pick_default(routes)
    assert chosen is not None
    assert chosen.destination == "0.0.0.0"


def test_pick_default_without_default_route() -> None:
    assert iphlpapi._pick_default([]) is None
    assert iphlpapi._pick_default([_route("10.0.0.0", 5, is_default=False)]) is None


def test_link_speed_treats_zero_and_unknown_as_missing() -> None:
    assert iphlpapi._link_speed(0) is None
    assert iphlpapi._link_speed(0xFFFFFFFFFFFFFFFF) is None
    assert iphlpapi._link_speed(1_000_000_000) == 1_000_000_000


def test_valid_prefix_len_limits() -> None:
    assert iphlpapi._valid_prefix_len(socket.AF_INET, 24) == 24
    assert iphlpapi._valid_prefix_len(socket.AF_INET, 33) is None
    assert iphlpapi._valid_prefix_len(socket.AF_INET6, 64) == 64
    assert iphlpapi._valid_prefix_len(socket.AF_INET6, 129) is None


# ---------------------------------------------------------------------------
# 结构体布局与解析（合成缓冲区）
# ---------------------------------------------------------------------------


def test_mib_if_row2_layout_matches_windows_sdk() -> None:
    assert ctypes.sizeof(iphlpapi._MIB_IF_ROW2) == 1352
    assert iphlpapi._MIB_IF_ROW2.InterfaceIndex.offset == _IF_INDEX_OFFSET
    assert iphlpapi._MIB_IF_ROW2.Alias.offset == _IF_ALIAS_OFFSET
    assert iphlpapi._MIB_IF_ROW2.ReceiveLinkSpeed.offset == _IF_RECEIVE_SPEED_OFFSET
    assert iphlpapi._MIB_IF_ROW2.InOctets.offset == _IF_IN_OCTETS_OFFSET
    assert iphlpapi._MIB_IF_ROW2.OutErrors.offset == _IF_OUT_ERRORS_OFFSET


def test_if_row_to_stats_parses_synthetic_buffer() -> None:
    raw = bytearray(ctypes.sizeof(iphlpapi._MIB_IF_ROW2))
    struct.pack_into("<I", raw, _IF_INDEX_OFFSET, 2)
    alias = "以太网".encode("utf-16-le") + b"\x00\x00"
    raw[_IF_ALIAS_OFFSET : _IF_ALIAS_OFFSET + len(alias)] = alias
    struct.pack_into("<Q", raw, _IF_RECEIVE_SPEED_OFFSET, 1_000_000_000)
    struct.pack_into("<Q", raw, _IF_IN_OCTETS_OFFSET, 1_409_341_934)
    struct.pack_into("<Q", raw, _IF_IN_DISCARDS_OFFSET, 11)
    struct.pack_into("<Q", raw, _IF_IN_ERRORS_OFFSET, 12)
    struct.pack_into("<Q", raw, _IF_OUT_OCTETS_OFFSET, 315_525_483)
    struct.pack_into("<Q", raw, _IF_OUT_DISCARDS_OFFSET, 13)
    struct.pack_into("<Q", raw, _IF_OUT_ERRORS_OFFSET, 14)

    buffer = ctypes.create_string_buffer(bytes(raw), len(raw))
    row = iphlpapi._MIB_IF_ROW2.from_address(ctypes.addressof(buffer))
    stats = iphlpapi._if_row_to_stats(row)

    assert stats.index == 2
    assert stats.name == "以太网"
    assert stats.in_octets == 1_409_341_934
    assert stats.in_discards == 11
    assert stats.in_errors == 12
    assert stats.out_octets == 315_525_483
    assert stats.out_discards == 13
    assert stats.out_errors == 14
    assert stats.speed_bps == 1_000_000_000


def test_if_row_to_stats_marks_unknown_speed() -> None:
    row = iphlpapi._MIB_IF_ROW2()
    row.ReceiveLinkSpeed = 0xFFFFFFFFFFFFFFFF
    assert iphlpapi._if_row_to_stats(row).speed_bps is None


def test_if_row_is_real_interface_filters_ndis_filter_layers() -> None:
    hardware = iphlpapi._MIB_IF_ROW2()
    hardware.InterfaceAndOperStatusFlags.HardwareInterface = 1
    hardware.InterfaceAndOperStatusFlags.ConnectorPresent = 1
    assert iphlpapi._if_row_is_real_interface(hardware) is True

    endpoint = iphlpapi._MIB_IF_ROW2()
    endpoint.InterfaceAndOperStatusFlags.EndPointInterface = 1
    assert iphlpapi._if_row_is_real_interface(endpoint) is True

    ndis_filter = iphlpapi._MIB_IF_ROW2()
    ndis_filter.InterfaceAndOperStatusFlags.FilterInterface = 1
    assert iphlpapi._if_row_is_real_interface(ndis_filter) is False

    # 过滤层即使同时带硬件位也必须排除（真机上过滤层通常只有 FilterInterface）。
    both = iphlpapi._MIB_IF_ROW2()
    both.InterfaceAndOperStatusFlags.HardwareInterface = 1
    both.InterfaceAndOperStatusFlags.FilterInterface = 1
    assert iphlpapi._if_row_is_real_interface(both) is False

    # 标志为 0 的逻辑接口（环回 / 隧道 / vEthernet / VPN）不是过滤层，保留。
    logical = iphlpapi._MIB_IF_ROW2()
    assert iphlpapi._if_row_is_real_interface(logical) is True


def test_iter_unicast_addresses_follows_chain() -> None:
    ipv4 = _sockaddr_buffer(socket.AF_INET, socket.inet_aton("192.0.2.4"))
    ipv6 = _sockaddr_buffer(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, "fe80::1"))

    first = iphlpapi._IP_ADAPTER_UNICAST_ADDRESS()
    second = iphlpapi._IP_ADAPTER_UNICAST_ADDRESS()
    first.Address.lpSockaddr = ctypes.addressof(ipv4)
    first.Address.iSockaddrLength = 16
    first.OnLinkPrefixLength = 24
    first.Next = ctypes.addressof(second)
    second.Address.lpSockaddr = ctypes.addressof(ipv6)
    second.Address.iSockaddrLength = 28
    second.OnLinkPrefixLength = 64
    second.Next = None

    nodes = list(iphlpapi._iter_unicast_addresses(ctypes.addressof(first)))
    assert len(nodes) == 2
    assert iphlpapi._socket_address_to_str(nodes[0].Address) == "192.0.2.4"
    assert iphlpapi._socket_address_to_str(nodes[1].Address) == "fe80::1"
    assert int(nodes[0].OnLinkPrefixLength) == 24
    assert int(nodes[1].OnLinkPrefixLength) == 64


def test_forward_row_to_route_adds_ipv4_interface_metric() -> None:
    row = iphlpapi._MIB_IPFORWARD_ROW2()
    row.InterfaceIndex = 2
    row.Metric = 1
    row.DestinationPrefix.Prefix.si_family = socket.AF_INET
    row.DestinationPrefix.Prefix.Ipv4.sin_addr = (ctypes.c_ubyte * 4)(0, 0, 0, 0)
    row.DestinationPrefix.PrefixLength = 0
    row.NextHop.si_family = socket.AF_INET
    row.NextHop.Ipv4.sin_addr = (ctypes.c_ubyte * 4)(192, 0, 2, 1)

    route = iphlpapi._forward_row_to_route(row, interface_metric=25)

    assert route is not None
    assert route.destination == "0.0.0.0"
    assert route.prefix_len == 0
    assert route.next_hop == "192.0.2.1"
    assert route.metric == 26
    assert route.is_default is True


def test_forward_row_to_route_keeps_ipv6_metric_and_drops_unspecified_hop() -> None:
    row = iphlpapi._MIB_IPFORWARD_ROW2()
    row.InterfaceIndex = 2
    row.Metric = 256
    row.DestinationPrefix.Prefix.si_family = socket.AF_INET6
    row.DestinationPrefix.PrefixLength = 0
    row.NextHop.si_family = socket.AF_INET6

    route = iphlpapi._forward_row_to_route(row, interface_metric=25)

    assert route is not None
    assert route.destination == "::"
    assert route.metric == 256
    assert route.next_hop is None
    assert route.is_default is True


# ---------------------------------------------------------------------------
# 真机只读验证（不写系统、不联网）
# ---------------------------------------------------------------------------


@_live_only
def test_live_adapters_returns_loopback_and_names() -> None:
    items = iphlpapi.adapters()
    assert items
    assert all(adapter.index > 0 for adapter in items)
    assert all(adapter.name for adapter in items)
    assert any(adapter.kind == "loopback" and not adapter.is_primary for adapter in items)


@_live_only
def test_live_addresses_belong_to_known_adapters() -> None:
    adapter_indexes = {adapter.index for adapter in iphlpapi.adapters()}
    items = iphlpapi.addresses()
    assert items
    assert all(item.adapter_index in adapter_indexes for item in items)
    assert all(item.family in (socket.AF_INET, socket.AF_INET6) for item in items)


@_live_only
def test_live_routes_and_default_route_are_consistent() -> None:
    items = iphlpapi.routes()
    assert items
    defaults = [route for route in items if route.is_default]
    assert defaults
    default = iphlpapi.default_route()
    assert default is not None
    assert default.is_default
    assert default.prefix_len == 0
    assert default.metric == min(route.metric for route in defaults)


@_live_only
def test_live_dns_servers_shape() -> None:
    items = iphlpapi.dns_servers()
    assert items
    for item in items:
        assert item.source in {"static", "dhcp", "none"}
        assert item.interface_name


@_live_only
def test_live_dns_servers_respect_adapter_filter() -> None:
    fake = Adapter(
        index=999_999,
        guid=None,
        name="不存在的接口",
        description="",
        mac=None,
        mtu=0,
        connected=False,
    )
    items = iphlpapi.dns_servers([fake])
    assert len(items) == 1
    assert items[0].adapter_index == 999_999
    assert items[0].servers == []
    assert items[0].source == "none"


@_live_only
def test_live_if_stats_counters() -> None:
    items = iphlpapi.if_stats()
    assert items
    assert all(item.index > 0 for item in items)
    assert all(item.in_octets >= 0 and item.out_octets >= 0 for item in items)
    assert all(
        item.in_errors >= 0 and item.out_errors >= 0 and item.in_discards >= 0 for item in items
    )


@_live_only
def test_live_if_stats_excludes_ndis_filter_layers() -> None:
    names = [item.name.casefold() for item in iphlpapi.if_stats()]
    assert all("filter-0000" not in name for name in names)
    assert all("-wfp " not in name for name in names)


@_live_only
def test_live_vpn_and_pseudo_interfaces_are_not_primary() -> None:
    for adapter in iphlpapi.adapters():
        if adapter.kind == "vpn":
            assert adapter.is_primary is False, adapter.name
        low = adapter.name.casefold()
        if any(marker in low for marker in ("pseudo-interface", "teredo", "isatap", "6to4")):
            assert adapter.is_primary is False, adapter.name
