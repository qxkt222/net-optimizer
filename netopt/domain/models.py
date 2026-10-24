# -*- coding: utf-8 -*-
"""系统读取层的领域模型 —— v2 与 ``netopt.models``（v1）并存的读路径契约。

这些模型是 :class:`netopt.system.api.SystemApi` 的唯一输入输出类型：
ctypes / winreg 实现负责填充它们，probes 只消费它们，不再解析本地化文本。

约定：

- 全部 ``frozen=True``：读到的系统状态是一份快照，不允许就地修改；
- 缺失值一律用 ``None``（或空集合）表达，不要用 ``0`` / ``-1`` / ``""`` 冒充；
- 字段全部带默认值或显式构造，方便 ``FakeSystemApi`` 造最小对象；
- 本模块无 IO、无业务逻辑，只定义数据结构。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PlatformInfo:
    """本机平台信息：OS 版本、Python 版本、是否管理员、区域设置。"""

    os_build: str | None = None
    windows_version: str | None = None
    python: str = ""
    is_admin: bool = False
    locale: str | None = None


@dataclass(frozen=True)
class Adapter:
    """一块网络适配器（网卡）。

    ``kind`` 取 ``ethernet | wlan | vpn | virtual | loopback | unknown``；
    ``is_primary`` 为 False 表示环回、虚拟交换机等不适合配置 DNS 的接口。
    ``guid`` 是注册表 ``Tcpip\\Parameters\\Interfaces`` 下对应的接口 GUID。
    """

    index: int
    guid: str | None
    name: str
    description: str
    mac: str | None
    mtu: int
    connected: bool
    kind: str = "unknown"
    is_primary: bool = True
    speed_bps: int | None = None
    media_type: str | None = None


@dataclass(frozen=True)
class Address:
    """适配器上的一个单播地址。

    ``family`` 直接复用 ``socket.AF_INET`` / ``socket.AF_INET6`` 的整数值，
    避免再定义一套枚举。``prefix_len`` 缺失时为 ``None``。
    """

    adapter_index: int
    family: int
    address: str
    prefix_len: int | None = None


@dataclass(frozen=True)
class InterfaceDns:
    """单个接口的 DNS 服务器与来源。

    ``source`` 取 ``static | dhcp | none``：静态配置优先于 DHCP，都没有则为
    ``none``。``servers`` 保持读取顺序，IPv4 / IPv6 混排。
    """

    adapter_index: int
    interface_name: str
    servers: list[str] = field(default_factory=list)
    source: str = "none"
    is_primary: bool = True


@dataclass(frozen=True)
class Route:
    """一条路由表项。``is_default`` 标记 ``0.0.0.0/0`` 或 ``::/0`` 默认路由。"""

    destination: str
    prefix_len: int
    next_hop: str | None
    interface_index: int
    metric: int
    is_default: bool = False


@dataclass(frozen=True)
class InterfaceStats:
    """接口计数器快照。数值来自 ``MIB_IF_ROW2``，调用方自行做差值。"""

    index: int
    name: str
    in_octets: int = 0
    out_octets: int = 0
    in_errors: int = 0
    out_errors: int = 0
    in_discards: int = 0
    out_discards: int = 0
    speed_bps: int | None = None


@dataclass(frozen=True)
class WifiState:
    """当前 WLAN 连接状态；未连接时 ``connected=False``，其余字段可为 ``None``。"""

    connected: bool = False
    interface: str | None = None
    ssid: str | None = None
    bssid: str | None = None
    signal_pct: int | None = None
    channel: int | None = None
    band: str | None = None
    rx_mbps: float | None = None
    tx_mbps: float | None = None
    state: str | None = None


@dataclass(frozen=True)
class WifiNetwork:
    """扫描到的一个周边 WiFi 网络（一个 BSS）。"""

    ssid: str | None = None
    bssid: str | None = None
    signal_pct: int | None = None
    channel: int | None = None
    band: str | None = None
    auth: str | None = None
    encryption: str | None = None


@dataclass(frozen=True)
class WifiScan:
    """一次周边网络扫描的结果。

    ``available=False`` 表示扫描本身不可用（如位置权限受限、wlanapi 缺失），
    此时 ``error`` 给出一句中文原因，``networks`` 为空。
    """

    networks: list[WifiNetwork] = field(default_factory=list)
    available: bool = True
    error: str | None = None


__all__ = [
    "Adapter",
    "Address",
    "InterfaceDns",
    "InterfaceStats",
    "PlatformInfo",
    "Route",
    "WifiNetwork",
    "WifiScan",
    "WifiState",
]
