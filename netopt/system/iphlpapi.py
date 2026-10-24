# -*- coding: utf-8 -*-
"""iphlpapi.dll 读路径 —— 适配器、地址、DNS、路由与接口计数。

v2 不再解析本地化的 ``netsh`` 文本，而是用 ctypes 直接调用 Windows IP Helper API：

- ``GetAdaptersAddresses``：适配器、单播地址、DNS、MTU、OperStatus；
- ``GetIpForwardTable2``：路由表，默认路由再按 metric 取最小；
- ``GetIfTable2``：接口字节数、错误、丢弃与链路速率（``MIB_IF_ROW2``）。

DLL 句柄在首次使用时惰性加载；任何调用失败都抛
:class:`netopt.system.api.SystemUnavailable`（带 API 名与错误码），
**不会**把「API 不可用」伪装成「没有网卡」。

结构体字段顺序与类型按 Windows SDK 10.0.26100 的 ``iptypes.h`` /
``netioapi.h`` / ``ifdef.h`` 定义，对应 64 位（x64）布局。访问结构体前会用
系统回报的 ``Length`` 校验，避免在旧版 Windows 上越界读取。
"""

from __future__ import annotations

import ctypes
import locale
import platform
import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, ClassVar

from netopt.domain.models import (
    Adapter,
    Address,
    InterfaceDns,
    InterfaceStats,
    PlatformInfo,
    Route,
)
from netopt.system.api import SystemUnavailable
from netopt.system.registry import dns_settings_for_adapters

__all__ = [
    "adapters",
    "addresses",
    "default_route",
    "dns_servers",
    "if_stats",
    "platform_info",
    "routes",
]

# ---------------------------------------------------------------------------
# 常量（Windows SDK：iptypes.h / netioapi.h / ifdef.h）
# ---------------------------------------------------------------------------

_AF_UNSPEC = 0

_ERROR_SUCCESS = 0
_ERROR_BUFFER_OVERFLOW = 111
_ERROR_NO_DATA = 232

_GAA_FLAG_SKIP_ANYCAST = 0x0002
_GAA_FLAG_SKIP_MULTICAST = 0x0004
_GAA_FLAG_INCLUDE_PREFIX = 0x0010
_GAA_FLAG_INCLUDE_GATEWAYS = 0x0080

#: 适配器信息：前缀长度用于地址，网关信息暂时不用，但保留与规格一致。
_GAA_FLAGS = (
    _GAA_FLAG_INCLUDE_PREFIX
    | _GAA_FLAG_INCLUDE_GATEWAYS
    | _GAA_FLAG_SKIP_ANYCAST
    | _GAA_FLAG_SKIP_MULTICAST
)

#: ``IF_OPER_STATUS`` 里的 up 值。
_IF_OPER_STATUS_UP = 1

_IF_TYPE_ETHERNET_CSMACD = 6
_IF_TYPE_PPP = 23
_IF_TYPE_SOFTWARE_LOOPBACK = 24
_IF_TYPE_PROP_VIRTUAL = 53
_IF_TYPE_IEEE80211 = 71
_IF_TYPE_TUNNEL = 131
_IF_TYPE_IEEE1394 = 144

#: ``TUNNEL_TYPE_NONE``：不是隧道接口。
_TUNNEL_TYPE_NONE = 0

#: 链路速率未知时系统返回全 1。
_UNKNOWN_LINK_SPEED = 0xFFFFFFFFFFFFFFFF

#: 名称关键字沿用 v1 的分类语义（见 ``netopt/parsers.py``），但不跨层 import。
_LOOPBACK_MARKERS = ("loopback", "环回")
_VIRTUAL_MARKERS = ("vethernet", "hyper-v", "default switch", "wsl", "virtualbox", "vmware", "虚拟")
_VPN_MARKERS = ("vpn", "tap-", "tunnel", "隧道", "wireguard", "openvpn", "tailscale", "zerotier")
_WLAN_MARKERS = ("wlan", "wi-fi", "wifi", "无线")

#: 隧道/伪接口：Teredo、ISATAP、6to4、隧道适配器都不是真实网卡。
_PSEUDO_MARKERS = ("pseudo-interface", "teredo", "isatap", "6to4", "tunnel adapter")

_IF_TYPE_NAMES = {
    _IF_TYPE_ETHERNET_CSMACD: "ethernet",
    _IF_TYPE_PPP: "ppp",
    _IF_TYPE_SOFTWARE_LOOPBACK: "loopback",
    _IF_TYPE_PROP_VIRTUAL: "virtual",
    _IF_TYPE_IEEE80211: "wlan",
    _IF_TYPE_TUNNEL: "tunnel",
    _IF_TYPE_IEEE1394: "ieee1394",
}


# ---------------------------------------------------------------------------
# ctypes 结构体（顺序、类型严格对齐 Windows SDK）
# ---------------------------------------------------------------------------


class _SOCKADDR_IN(ctypes.Structure):
    """IPv4 ``SOCKADDR_IN``（16 字节）。"""

    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


class _SOCKADDR_IN6(ctypes.Structure):
    """IPv6 ``SOCKADDR_IN6``（28 字节）。"""

    _fields_ = [
        ("sin6_family", ctypes.c_ushort),
        ("sin6_port", ctypes.c_ushort),
        ("sin6_flowinfo", ctypes.c_ulong),
        ("sin6_addr", ctypes.c_ubyte * 16),
        ("sin6_scope_id", ctypes.c_ulong),
    ]


class _SOCKADDR_INET(ctypes.Union):
    """``SOCKADDR_INET``：IPv4 / IPv6 地址的联合体。"""

    _fields_: ClassVar[list[tuple[str, Any]]] = [
        ("Ipv4", _SOCKADDR_IN),
        ("Ipv6", _SOCKADDR_IN6),
        ("si_family", ctypes.c_ushort),
    ]


class _SOCKET_ADDRESS(ctypes.Structure):
    """``SOCKET_ADDRESS``：裸 sockaddr 指针 + 长度。"""

    _fields_ = [
        ("lpSockaddr", ctypes.c_void_p),
        ("iSockaddrLength", ctypes.c_int),
    ]


class _GUID(ctypes.Structure):
    """Windows ``GUID``（16 字节，4 字节对齐）。"""

    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _MIB_IF_ROW2_INTERFACE_FLAGS(ctypes.Structure):
    """``MIB_IF_ROW2.InterfaceAndOperStatusFlags``：8 个 1 位标志，共 1 字节。"""

    _fields_ = [
        ("HardwareInterface", ctypes.c_ubyte, 1),
        ("FilterInterface", ctypes.c_ubyte, 1),
        ("ConnectorPresent", ctypes.c_ubyte, 1),
        ("NotAuthenticated", ctypes.c_ubyte, 1),
        ("NotMediaConnected", ctypes.c_ubyte, 1),
        ("Paused", ctypes.c_ubyte, 1),
        ("LowPower", ctypes.c_ubyte, 1),
        ("EndPointInterface", ctypes.c_ubyte, 1),
    ]


class _MIB_IF_ROW2(ctypes.Structure):
    """``MIB_IF_ROW2``（Windows SDK 10.0.26100，x64 下 1352 字节）。"""

    _fields_ = [
        ("InterfaceLuid", ctypes.c_ulonglong),
        ("InterfaceIndex", ctypes.c_ulong),
        ("InterfaceGuid", _GUID),
        ("Alias", ctypes.c_wchar * 257),
        ("Description", ctypes.c_wchar * 257),
        ("PhysicalAddressLength", ctypes.c_ulong),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
        ("TunnelType", ctypes.c_ulong),
        ("MediaType", ctypes.c_ulong),
        ("PhysicalMediumType", ctypes.c_ulong),
        ("AccessType", ctypes.c_ulong),
        ("DirectionType", ctypes.c_ulong),
        ("InterfaceAndOperStatusFlags", _MIB_IF_ROW2_INTERFACE_FLAGS),
        ("OperStatus", ctypes.c_ulong),
        ("AdminStatus", ctypes.c_ulong),
        ("MediaConnectState", ctypes.c_ulong),
        ("NetworkGuid", _GUID),
        ("ConnectionType", ctypes.c_ulong),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("InOctets", ctypes.c_ulonglong),
        ("InUcastPkts", ctypes.c_ulonglong),
        ("InNUcastPkts", ctypes.c_ulonglong),
        ("InDiscards", ctypes.c_ulonglong),
        ("InErrors", ctypes.c_ulonglong),
        ("InUnknownProtos", ctypes.c_ulonglong),
        ("InUcastOctets", ctypes.c_ulonglong),
        ("InMulticastOctets", ctypes.c_ulonglong),
        ("InBroadcastOctets", ctypes.c_ulonglong),
        ("OutOctets", ctypes.c_ulonglong),
        ("OutUcastPkts", ctypes.c_ulonglong),
        ("OutNUcastPkts", ctypes.c_ulonglong),
        ("OutDiscards", ctypes.c_ulonglong),
        ("OutErrors", ctypes.c_ulonglong),
        ("OutUcastOctets", ctypes.c_ulonglong),
        ("OutMulticastOctets", ctypes.c_ulonglong),
        ("OutBroadcastOctets", ctypes.c_ulonglong),
        ("OutQLen", ctypes.c_ulonglong),
    ]


class _MIB_IF_TABLE2(ctypes.Structure):
    """``MIB_IF_TABLE2`` 头部；``Table`` 是柔性数组，按偏移手工遍历。"""

    _fields_ = [("NumEntries", ctypes.c_ulong)]


class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    """``IP_ADAPTER_UNICAST_ADDRESS_LH``（x64 下 64 字节）。"""

    _fields_ = [
        ("Length", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
        ("Next", ctypes.c_void_p),
        ("Address", _SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_ulong),
        ("SuffixOrigin", ctypes.c_ulong),
        ("DadState", ctypes.c_ulong),
        ("ValidLifetime", ctypes.c_ulong),
        ("PreferredLifetime", ctypes.c_ulong),
        ("LeaseLifetime", ctypes.c_ulong),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]


class _IP_ADAPTER_DNS_SERVER_ADDRESS(ctypes.Structure):
    """``IP_ADAPTER_DNS_SERVER_ADDRESS_XP``。"""

    _fields_ = [
        ("Length", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
        ("Next", ctypes.c_void_p),
        ("Address", _SOCKET_ADDRESS),
    ]


class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
    """``IP_ADAPTER_ADDRESSES_LH``（x64 下 448 字节）。

    字段按 SDK 顺序完整声明以保持偏移；其中链路速率、IPv4 接口 metric 与
    ``FirstDnsSuffix`` 之后的内容本模块不读，但保留以校验结构版本。
    ``Next`` 在 ``_read_adapter_records`` 里按指针手工遍历。
    """

    _fields_ = [
        ("Length", ctypes.c_ulong),
        ("IfIndex", ctypes.c_ulong),
        ("Next", ctypes.c_void_p),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.c_void_p),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
        ("Mtu", ctypes.c_ulong),
        ("IfType", ctypes.c_ulong),
        ("OperStatus", ctypes.c_ulong),
        ("Ipv6IfIndex", ctypes.c_ulong),
        ("ZoneIndices", ctypes.c_ulong * 16),
        ("FirstPrefix", ctypes.c_void_p),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("FirstWinsServerAddress", ctypes.c_void_p),
        ("FirstGatewayAddress", ctypes.c_void_p),
        ("Ipv4Metric", ctypes.c_ulong),
        ("Ipv6Metric", ctypes.c_ulong),
        ("Luid", ctypes.c_ulonglong),
        ("Dhcpv4Server", _SOCKET_ADDRESS),
        ("CompartmentId", ctypes.c_ulong),
        ("NetworkGuid", _GUID),
        ("ConnectionType", ctypes.c_ulong),
        ("TunnelType", ctypes.c_ulong),
        ("Dhcpv6Server", _SOCKET_ADDRESS),
        ("Dhcpv6ClientDuid", ctypes.c_ubyte * 130),
        ("Dhcpv6ClientDuidLength", ctypes.c_ulong),
        ("Dhcpv6Iaid", ctypes.c_ulong),
        ("FirstDnsSuffix", ctypes.c_void_p),
    ]


class _IP_ADDRESS_PREFIX(ctypes.Structure):
    """``IP_ADDRESS_PREFIX``：前缀地址 + 前缀长度。"""

    _fields_ = [
        ("Prefix", _SOCKADDR_INET),
        ("PrefixLength", ctypes.c_ubyte),
    ]


class _MIB_IPFORWARD_ROW2(ctypes.Structure):
    """``MIB_IPFORWARD_ROW2``（x64 下 104 字节）。"""

    _fields_ = [
        ("InterfaceLuid", ctypes.c_ulonglong),
        ("InterfaceIndex", ctypes.c_ulong),
        ("DestinationPrefix", _IP_ADDRESS_PREFIX),
        ("NextHop", _SOCKADDR_INET),
        ("SitePrefixLength", ctypes.c_ubyte),
        ("ValidLifetime", ctypes.c_ulong),
        ("PreferredLifetime", ctypes.c_ulong),
        ("Metric", ctypes.c_ulong),
        ("Protocol", ctypes.c_ulong),
        ("Loopback", ctypes.c_ubyte),
        ("AutoconfigureAddress", ctypes.c_ubyte),
        ("Publish", ctypes.c_ubyte),
        ("Immortal", ctypes.c_ubyte),
        ("Age", ctypes.c_ulong),
        ("Origin", ctypes.c_ulong),
    ]


class _MIB_IPFORWARD_TABLE2(ctypes.Structure):
    """``MIB_IPFORWARD_TABLE2`` 头部；``Table`` 是柔性数组。"""

    _fields_ = [("NumEntries", ctypes.c_ulong)]


def _align_up(value: int, alignment: int) -> int:
    """把 ``value`` 向上对齐到 ``alignment`` 的整数倍。"""
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


#: 柔性数组在表头之后的偏移：``ULONG`` 之后按行结构对齐。
_IF_ROW_SIZE = ctypes.sizeof(_MIB_IF_ROW2)
_IF_TABLE_OFFSET = _align_up(ctypes.sizeof(ctypes.c_ulong), ctypes.alignment(_MIB_IF_ROW2))
_FORWARD_ROW_SIZE = ctypes.sizeof(_MIB_IPFORWARD_ROW2)
_FORWARD_TABLE_OFFSET = _align_up(
    ctypes.sizeof(ctypes.c_ulong), ctypes.alignment(_MIB_IPFORWARD_ROW2)
)


# ---------------------------------------------------------------------------
# DLL 惰性加载
# ---------------------------------------------------------------------------

_dll: ctypes.WinDLL | None = None


def _configure(dll: ctypes.WinDLL) -> None:
    """声明各 API 的参数与返回类型，避免 ctypes 默认按 int 截断指针。"""
    dll.GetAdaptersAddresses.restype = ctypes.c_ulong
    dll.GetAdaptersAddresses.argtypes = [
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]

    dll.GetIfTable2.restype = ctypes.c_ulong
    dll.GetIfTable2.argtypes = [ctypes.POINTER(ctypes.POINTER(_MIB_IF_TABLE2))]

    dll.GetIpForwardTable2.restype = ctypes.c_ulong
    dll.GetIpForwardTable2.argtypes = [
        ctypes.c_ushort,
        ctypes.POINTER(ctypes.POINTER(_MIB_IPFORWARD_TABLE2)),
    ]

    dll.FreeMibTable.restype = None
    dll.FreeMibTable.argtypes = [ctypes.c_void_p]


def _iphlpapi() -> ctypes.WinDLL:
    """返回惰性加载的 iphlpapi.dll 句柄；缺失时抛 :class:`SystemUnavailable`。"""
    global _dll
    if _dll is None:
        try:
            dll = ctypes.WinDLL("iphlpapi", use_last_error=True)
        except OSError as exc:
            raise SystemUnavailable(f"无法加载 iphlpapi.dll：{exc}") from exc
        _configure(dll)
        _dll = dll
    return _dll


def _api_error(api: str, code: int) -> SystemUnavailable:
    """把 Win32 错误码包装成带 API 名的可读异常。"""
    try:
        text = ctypes.FormatError(code).strip()
    except OSError:
        text = ""
    detail = f"错误码 {code}：{text}" if text else f"错误码 {code}"
    return SystemUnavailable(f"{api} 调用失败（{detail}）")


# ---------------------------------------------------------------------------
# 解析辅助函数
# ---------------------------------------------------------------------------


def _decode_wchar(value: ctypes.Array[ctypes.c_wchar]) -> str:
    """把 ``WCHAR`` 定长数组解码成字符串，遇到 NUL 即停止。"""
    chars: list[str] = []
    for char in value:
        if char == "\x00":
            break
        chars.append(char)
    return "".join(chars)


def _decode_ascii(raw: bytes | None) -> str:
    """解码 ``PCHAR``（适配器名通常是 ASCII GUID）；空指针返回空串。"""
    if not raw:
        return ""
    return raw.decode("ascii", errors="replace")


def _mac_to_str(raw: bytes | None) -> str | None:
    """把 6 字节硬件地址格式化成 ``aa:bb:cc:dd:ee:ff``；空地址返回 ``None``。"""
    if not raw:
        return None
    return ":".join(f"{octet:02x}" for octet in raw)


def _mask_to_prefix(mask: str) -> int:
    """把点分十进制 IPv4 掩码转换成前缀长度（``255.255.255.0`` → 24）。

    位不连续的掩码视为非法并抛 ``ValueError``。v2 的路由 API 直接给出
    ``PrefixLength``，此函数保留给只提供掩码的旧式数据源与测试使用。
    """
    parts = mask.split(".")
    if len(parts) != 4:
        raise ValueError(f"非法 IPv4 掩码：{mask!r}")
    value = 0
    for part in parts:
        try:
            octet = int(part)
        except ValueError as exc:
            raise ValueError(f"非法 IPv4 掩码：{mask!r}") from exc
        if not 0 <= octet <= 255:
            raise ValueError(f"非法 IPv4 掩码：{mask!r}")
        value = (value << 8) | octet
    prefix = bin(value).count("1")
    expected = ((1 << prefix) - 1) << (32 - prefix) if prefix else 0
    if value != expected:
        raise ValueError(f"非法 IPv4 掩码（位不连续）：{mask!r}")
    return prefix


def _sockaddr_family(sockaddr: int) -> int:
    """读取 ``SOCKADDR`` 的地址族（前两个字节）。"""
    family: int = ctypes.cast(sockaddr, ctypes.POINTER(ctypes.c_ushort)).contents.value
    return family


def _sockaddr_to_str(sockaddr: int | None, family: int | None = None) -> str | None:
    """把 ``SOCKADDR`` 指针转成地址字符串；未知地址族返回 ``None``。

    长度由地址族推导：IPv4 地址在偏移 4（2 字节 family + 2 字节 port），
    IPv6 地址在偏移 8（2 + 2 + 4 字节 flowinfo）。
    """
    if not sockaddr:
        return None
    family = _sockaddr_family(sockaddr) if family is None else family
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, ctypes.string_at(sockaddr + 4, 4))
    if family == socket.AF_INET6:
        return socket.inet_ntop(socket.AF_INET6, ctypes.string_at(sockaddr + 8, 16))
    return None


def _socket_address_to_str(address: _SOCKET_ADDRESS) -> str | None:
    """把 ``SOCKET_ADDRESS`` 转成地址字符串。"""
    pointer = address.lpSockaddr
    return _sockaddr_to_str(int(pointer) if pointer else None)


def _sockaddr_inet_to_str(address: _SOCKADDR_INET) -> str | None:
    """把 ``SOCKADDR_INET`` 联合体转成地址字符串。"""
    family = int(address.si_family)
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, bytes(address.Ipv4.sin_addr))
    if family == socket.AF_INET6:
        return socket.inet_ntop(socket.AF_INET6, bytes(address.Ipv6.sin6_addr))
    return None


def _is_unspecified(address: str) -> bool:
    """判断 ``0.0.0.0`` / ``::``（on-link 路由的下一跳写法）。"""
    # 这里比较的是路由表里的未指定地址，不是服务监听地址
    return address in ("0.0.0.0", "::")  # nosec B104


def _if_type_name(if_type: int) -> str:
    """把 ``IFTYPE`` 转成可读介质名，未知类型保留数字。"""
    return _IF_TYPE_NAMES.get(if_type, f"iftype-{if_type}")


def _classify(name: str, if_type: int, tunnel_type: int = _TUNNEL_TYPE_NONE) -> tuple[str, bool]:
    """按 ``IfType`` 与名称给接口分类，返回 ``(kind, is_primary)``。

    - loopback / 虚拟交换机不参与 DNS 配置（``is_primary=False``）；
    - **VPN 默认也不参与 DNS 修改**（``is_primary=False``）：v1 的 D11 要求
      不打断 VPN 的 split-DNS。确需修改 VPN 的 DNS 时，由上层显式覆盖，
      不能默认动；
    - Teredo / ISATAP / 6to4 / 隧道适配器等伪接口按 ``vpn`` 归类，同样
      ``is_primary=False`` —— 它们没有可配置 DNS 的实体网卡；
    - 只有物理网卡 / 无线接口保持 ``is_primary=True``。

    判定顺序：环回 → 虚拟 → VPN/隧道 → WLAN → 以太网。
    """
    low = name.casefold()
    if if_type == _IF_TYPE_SOFTWARE_LOOPBACK or any(marker in low for marker in _LOOPBACK_MARKERS):
        return "loopback", False
    if if_type == _IF_TYPE_PROP_VIRTUAL or any(marker in low for marker in _VIRTUAL_MARKERS):
        return "virtual", False
    if (
        if_type == _IF_TYPE_TUNNEL
        or tunnel_type != _TUNNEL_TYPE_NONE
        or any(marker in low for marker in _VPN_MARKERS)
        or any(marker in low for marker in _PSEUDO_MARKERS)
    ):
        return "vpn", False
    if if_type == _IF_TYPE_IEEE80211 or any(marker in low for marker in _WLAN_MARKERS):
        return "wlan", True
    if if_type in (_IF_TYPE_ETHERNET_CSMACD, _IF_TYPE_IEEE1394):
        return "ethernet", True
    return "unknown", True


def _link_speed(raw: int) -> int | None:
    """链路速率：0 与全 1 都表示未知，按缺失值返回 ``None``。"""
    if raw in (0, _UNKNOWN_LINK_SPEED):
        return None
    return raw


def _valid_prefix_len(family: int, raw: int) -> int | None:
    """校验前缀长度：IPv4 上限 32，IPv6 上限 128，非法值返回 ``None``。"""
    limit = 32 if family == socket.AF_INET else 128
    return raw if 0 <= raw <= limit else None


def _iter_unicast_addresses(first: int | None) -> Iterator[_IP_ADAPTER_UNICAST_ADDRESS]:
    """遍历 ``IP_ADAPTER_UNICAST_ADDRESS`` 单向链表。"""
    address = int(first or 0)
    while address:
        node = _IP_ADAPTER_UNICAST_ADDRESS.from_address(address)
        yield node
        address = int(node.Next or 0)


def _iter_dns_addresses(first: int | None) -> Iterator[_IP_ADAPTER_DNS_SERVER_ADDRESS]:
    """遍历 ``IP_ADAPTER_DNS_SERVER_ADDRESS`` 单向链表。"""
    address = int(first or 0)
    while address:
        node = _IP_ADAPTER_DNS_SERVER_ADDRESS.from_address(address)
        yield node
        address = int(node.Next or 0)


def _if_row_to_stats(row: _MIB_IF_ROW2) -> InterfaceStats:
    """把一行 ``MIB_IF_ROW2`` 转成 :class:`InterfaceStats`。"""
    return InterfaceStats(
        index=int(row.InterfaceIndex),
        name=_decode_wchar(row.Alias),
        in_octets=int(row.InOctets),
        out_octets=int(row.OutOctets),
        in_errors=int(row.InErrors),
        out_errors=int(row.OutErrors),
        in_discards=int(row.InDiscards),
        out_discards=int(row.OutDiscards),
        speed_bps=_link_speed(int(row.ReceiveLinkSpeed)),
    )


def _if_row_is_real_interface(row: _MIB_IF_ROW2) -> bool:
    """判断一行 ``MIB_IF_ROW2`` 是否是可枚举的真实接口（而非 NDIS 过滤层）。

    依据 ``InterfaceAndOperStatusFlags``：

    - ``FilterInterface`` 置位 → 绑定在网卡上的 NDIS 过滤驱动，名字形如
      ``以太网-WFP Native MAC Layer LightWeight Filter-0000``，不是网卡，排除；
    - ``HardwareInterface`` / ``EndPointInterface`` 置位 → 物理网卡或端点接口，保留；
    - 其余行按真实接口保留。取舍说明：本机实测环回、Teredo、vEthernet、
      Radmin VPN、虚拟交换机的标志字节是 0、``EndPointInterface`` 并未置位，
      蓝牙则只有 ``NotMediaConnected``；它们都不是过滤层，且上层会按接口
      索引取计数器，丢掉反而会让 ``adapters()`` 与 ``if_stats()`` 对不上。
    """
    flags = row.InterfaceAndOperStatusFlags
    # HardwareInterface / EndPointInterface 置位的行是物理网卡与端点接口；
    # 标志为 0 的行是环回、隧道、VPN、vEthernet 等逻辑接口（本机实测）。
    # 两类都不是过滤层，一并保留。
    return not int(flags.FilterInterface)


def _pick_default(routes: list[Route]) -> Route | None:
    """在默认路由里取 metric 最小的一条；同分时优先 IPv4。

    Windows 的 IPv4 / IPv6 路由表各有独立 metric，数值只在本族内有意义；
    同分时优先 IPv4，与 ``route print -4 0.0.0.0`` 的结果对齐。
    """
    defaults = [route for route in routes if route.is_default]
    if not defaults:
        return None
    return min(
        defaults,
        key=lambda route: (route.metric, 0 if ":" not in route.destination else 1),
    )


# ---------------------------------------------------------------------------
# GetAdaptersAddresses：适配器、地址、DNS
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _AdapterRecord:
    """一次 ``GetAdaptersAddresses`` 读到的单块适配器信息。

    ``ipv4_metric`` 是接口本身的 metric；IPv4 路由的
    ``MIB_IPFORWARD_ROW2.Metric`` 只是路由偏移，需要加上它才与
    ``route print`` 的「跃点数」一致。
    """

    adapter: Adapter
    addresses: list[Address] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    ipv4_metric: int = 0


def _read_adapter_records() -> list[_AdapterRecord]:
    """调用 ``GetAdaptersAddresses`` 并解析为 :class:`_AdapterRecord` 列表。"""
    dll = _iphlpapi()
    size = ctypes.c_ulong(0)
    ret = int(dll.GetAdaptersAddresses(_AF_UNSPEC, _GAA_FLAGS, None, None, ctypes.byref(size)))
    if ret not in (_ERROR_SUCCESS, _ERROR_BUFFER_OVERFLOW):
        raise _api_error("GetAdaptersAddresses", ret)
    if size.value == 0:
        raise SystemUnavailable("GetAdaptersAddresses 返回的缓冲区长度为 0，无法读取适配器")

    buffer = ctypes.create_string_buffer(size.value)
    ret = int(
        dll.GetAdaptersAddresses(
            _AF_UNSPEC,
            _GAA_FLAGS,
            None,
            ctypes.cast(buffer, ctypes.c_void_p),
            ctypes.byref(size),
        )
    )
    if ret == _ERROR_NO_DATA:
        raise SystemUnavailable(
            "GetAdaptersAddresses 返回错误码 232（ERROR_NO_DATA）：系统未报告任何适配器"
        )
    if ret != _ERROR_SUCCESS:
        raise _api_error("GetAdaptersAddresses", ret)

    records: list[_AdapterRecord] = []
    address = ctypes.addressof(buffer)
    while address:
        item = _IP_ADAPTER_ADDRESSES.from_address(address)
        length = int(item.Length)
        if length <= 0 or ctypes.sizeof(_IP_ADAPTER_ADDRESSES) > length:
            raise SystemUnavailable(
                "GetAdaptersAddresses 返回的结构版本不匹配："
                f"系统 Length={length}，本模块期望 {ctypes.sizeof(_IP_ADAPTER_ADDRESSES)}"
            )
        records.append(_adapter_record_from_item(item))
        address = int(item.Next or 0)
    return records


def _adapter_record_from_item(item: _IP_ADAPTER_ADDRESSES) -> _AdapterRecord:
    """从一条 ``IP_ADAPTER_ADDRESSES`` 解析出适配器、地址与 DNS。"""
    index = int(item.IfIndex)
    if_type = int(item.IfType)
    tunnel_type = int(item.TunnelType)

    friendly = item.FriendlyName
    name = friendly if isinstance(friendly, str) and friendly else ""
    adapter_name = _decode_ascii(item.AdapterName)
    if not name:
        name = adapter_name or f"适配器 {index}"
    description = item.Description if isinstance(item.Description, str) else ""

    kind, is_primary = _classify(name, if_type, tunnel_type)

    address_length = min(int(item.PhysicalAddressLength), 8)
    mac = _mac_to_str(bytes(item.PhysicalAddress[:address_length]))
    speed_bps = _link_speed(int(item.ReceiveLinkSpeed))

    adapter = Adapter(
        index=index,
        guid=adapter_name or None,
        name=name,
        description=description,
        mac=mac,
        mtu=int(item.Mtu),
        connected=int(item.OperStatus) == _IF_OPER_STATUS_UP,
        kind=kind,
        is_primary=is_primary,
        speed_bps=speed_bps,
        media_type=_if_type_name(if_type),
    )

    addresses: list[Address] = []
    for node in _iter_unicast_addresses(item.FirstUnicastAddress):
        pointer = node.Address.lpSockaddr
        if not pointer:
            continue
        family = _sockaddr_family(int(pointer))
        text = _sockaddr_to_str(int(pointer), family)
        if text is None:
            continue
        addresses.append(
            Address(
                adapter_index=index,
                family=family,
                address=text,
                prefix_len=_valid_prefix_len(family, int(node.OnLinkPrefixLength)),
            )
        )

    dns: list[str] = []
    seen: set[str] = set()
    for dns_node in _iter_dns_addresses(item.FirstDnsServerAddress):
        server = _socket_address_to_str(dns_node.Address)
        if server and server not in seen:
            seen.add(server)
            dns.append(server)

    return _AdapterRecord(
        adapter=adapter,
        addresses=addresses,
        dns=dns,
        ipv4_metric=int(item.Ipv4Metric),
    )


# ---------------------------------------------------------------------------
# GetIpForwardTable2：路由表
# ---------------------------------------------------------------------------


def _forward_row_to_route(row: _MIB_IPFORWARD_ROW2, interface_metric: int = 0) -> Route | None:
    """把一行 ``MIB_IPFORWARD_ROW2`` 转成 :class:`Route`；无法解析时返回 ``None``。

    IPv4 的 ``Metric`` 字段只是路由偏移，实际跃点数还要加上接口 metric
    （``route print`` 展示的就是两者之和）；IPv6 路由表直接给出完整 metric，
    与 ``netsh interface ipv6 show route`` 一致，不再叠加。
    """
    destination = _sockaddr_inet_to_str(row.DestinationPrefix.Prefix)
    if destination is None:
        return None
    prefix_len = int(row.DestinationPrefix.PrefixLength)
    next_hop = _sockaddr_inet_to_str(row.NextHop)
    if next_hop is not None and _is_unspecified(next_hop):
        next_hop = None
    metric = int(row.Metric) if ":" in destination else int(row.Metric) + interface_metric
    return Route(
        destination=destination,
        prefix_len=prefix_len,
        next_hop=next_hop,
        interface_index=int(row.InterfaceIndex),
        metric=metric,
        is_default=prefix_len == 0 and _is_unspecified(destination),
    )


# ---------------------------------------------------------------------------
# 对外接口
# ---------------------------------------------------------------------------


def platform_info() -> PlatformInfo:
    """返回 OS 版本、Python 版本、是否管理员与区域设置。

    Windows 版本用 ``sys.getwindowsversion()``（内部即 RtlGetVersion，不受
    应用清单影响）；管理员判定调用 ``shell32.IsUserAnAdmin``。
    """
    version = sys.getwindowsversion()
    return PlatformInfo(
        os_build=str(version.build),
        windows_version=f"{version.major}.{version.minor}.{version.build}",
        python=platform.python_version(),
        is_admin=_is_admin(),
        locale=_locale_name(),
    )


def _is_admin() -> bool:
    """是否以管理员身份运行；判定失败时按非管理员处理。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _locale_name() -> str | None:
    """当前区域设置（形如 ``zh_CN.UTF-8``）；拿不到返回 ``None``。"""
    try:
        language, encoding = locale.getlocale()
    except ValueError:
        return None
    parts = [part for part in (language, encoding) if part]
    return ".".join(parts) or None


def adapters() -> list[Adapter]:
    """返回所有网络适配器（含虚拟网卡与环回）。"""
    return [record.adapter for record in _read_adapter_records()]


def addresses() -> list[Address]:
    """返回所有适配器上的单播地址（IPv4 + IPv6）。"""
    result: list[Address] = []
    for record in _read_adapter_records():
        result.extend(record.addresses)
    return result


def dns_servers(adapters: list[Adapter] | None = None) -> list[InterfaceDns]:
    """返回每个接口的 DNS 服务器与来源（``static`` / ``dhcp`` / ``none``）。

    服务器列表取自 ``GetAdaptersAddresses``（IPv4 / IPv6 都收，保持系统顺序），
    ``source`` 取自注册表判定。注册表读不到时 ``source`` 为 ``none``，
    但 API 读到的服务器仍然保留。

    参数 ``adapters`` 给出时只返回这些接口的结果，否则返回系统里的全部接口。
    """
    records = _read_adapter_records()
    by_index = {record.adapter.index: record for record in records}
    selected = list(adapters) if adapters is not None else [record.adapter for record in records]

    settings = {setting.adapter_index: setting for setting in dns_settings_for_adapters(selected)}
    result: list[InterfaceDns] = []
    for adapter in selected:
        setting = settings.get(adapter.index)
        record = by_index.get(adapter.index)
        servers = list(record.dns) if record else []
        if not servers and setting is not None:
            servers = list(setting.servers)
        result.append(
            InterfaceDns(
                adapter_index=adapter.index,
                interface_name=adapter.name,
                servers=servers,
                source=setting.source if setting is not None else "none",
                is_primary=adapter.is_primary,
            )
        )
    return result


def routes() -> list[Route]:
    """返回 IPv4 + IPv6 路由表。

    IPv4 的 ``metric`` 按 ``route print`` 口径（路由 metric + 接口 metric）；
    IPv6 按路由表原值。默认路由可用 :func:`default_route` 直接取。
    """
    interface_metrics = {
        record.adapter.index: record.ipv4_metric for record in _read_adapter_records()
    }
    dll = _iphlpapi()
    table = ctypes.POINTER(_MIB_IPFORWARD_TABLE2)()
    ret = int(dll.GetIpForwardTable2(_AF_UNSPEC, ctypes.byref(table)))
    if ret != _ERROR_SUCCESS:
        raise _api_error("GetIpForwardTable2", ret)

    try:
        count = int(table.contents.NumEntries)
        if count == 0:
            raise SystemUnavailable("GetIpForwardTable2 返回 0 条路由，与系统状态不符")
        base = ctypes.addressof(table.contents)
        result: list[Route] = []
        for offset in range(count):
            row = _MIB_IPFORWARD_ROW2.from_address(
                base + _FORWARD_TABLE_OFFSET + offset * _FORWARD_ROW_SIZE
            )
            interface_index = int(row.InterfaceIndex)
            route = _forward_row_to_route(row, interface_metrics.get(interface_index, 0))
            if route is not None:
                result.append(route)
        return result
    finally:
        dll.FreeMibTable(ctypes.cast(table, ctypes.c_void_p))


def default_route() -> Route | None:
    """返回 metric 最小的默认路由；没有默认路由时返回 ``None``。"""
    return _pick_default(routes())


def if_stats() -> list[InterfaceStats]:
    """返回各接口的字节数、错误、丢弃与链路速率。"""
    dll = _iphlpapi()
    table = ctypes.POINTER(_MIB_IF_TABLE2)()
    ret = int(dll.GetIfTable2(ctypes.byref(table)))
    if ret != _ERROR_SUCCESS:
        raise _api_error("GetIfTable2", ret)

    try:
        count = int(table.contents.NumEntries)
        if count == 0:
            raise SystemUnavailable("GetIfTable2 返回 0 个接口，与系统状态不符")
        base = ctypes.addressof(table.contents)
        result: list[InterfaceStats] = []
        for offset in range(count):
            row = _MIB_IF_ROW2.from_address(base + _IF_TABLE_OFFSET + offset * _IF_ROW_SIZE)
            if not _if_row_is_real_interface(row):
                continue
            result.append(_if_row_to_stats(row))
        if not result:
            raise SystemUnavailable("GetIfTable2 过滤后没有真实接口，与系统状态不符")
        return result
    finally:
        dll.FreeMibTable(ctypes.cast(table, ctypes.c_void_p))
