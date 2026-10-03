# -*- coding: utf-8 -*-
"""领域数据模型 —— 纯 dataclass，无 IO，无业务逻辑。

这是**冻结契约**：parsers 产出它们，probes 返回它们，render 消费它们。
改动字段名或含义会同时影响四方，改之前先确认。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PingStat:
    """一次 ping 的统计结果。

    ``avg_ms`` 为 None 表示一个回复都没收到（不可达）。
    ``loss_pct`` 在不可达时为 100.0。
    """

    target: str
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    jitter_ms: float | None = None
    loss_pct: float = 100.0
    replies: int = 0
    raw: str = ""

    @property
    def reachable(self) -> bool:
        return self.replies > 0


@dataclass(frozen=True)
class Interface:
    """一个网络接口。来自 ``netsh interface ipv4 show interfaces``。"""

    name: str
    index: int
    mtu: int
    connected: bool
    kind: str = "unknown"  # ethernet | wlan | vpn | virtual | loopback | unknown
    is_primary: bool = True  # False 表示不应在其上配置 DNS（环回、虚拟交换机等）

    @property
    def configurable(self) -> bool:
        """是否适合在上面设置 DNS 服务器地址。"""
        return self.connected and self.is_primary


@dataclass(frozen=True)
class Gateway:
    """IPv4 默认网关。来自 ``route print -4`` 的**活动路由**段。"""

    ip: str
    interface_ip: str
    metric: int
    interface_index: int | None = None


@dataclass(frozen=True)
class DnsConfig:
    """单个接口的 DNS 配置。"""

    interface: str
    index: int | None = None
    servers: list[str] = field(default_factory=list)
    source: str = "none"  # static | dhcp | none


@dataclass(frozen=True)
class MtuResult:
    """路径 MTU 探测结果。

    ``payload`` 是 ICMP 负载字节数，``mtu`` = payload + 28（IP 头 20 + ICMP 头 8）。
    ``verified`` 为 True 表示边界经过重复确认；False 表示探测中遇到过超时等
    不确定信号，结果仅供参考。
    """

    mtu: int | None = None
    payload: int | None = None
    verified: bool = False

    @property
    def found(self) -> bool:
        return self.mtu is not None

    def is_standard_ethernet(self) -> bool:
        """1500 是标准以太网 MTU。"""
        return self.mtu is not None and self.mtu >= 1500

    def is_pppoe(self) -> bool:
        """1492 = 1500 - 8(PPPoE 头)，国内宽带最常见。"""
        return self.mtu == 1492


@dataclass(frozen=True)
class WlanInfo:
    """当前 WLAN 接口状态。来自 ``netsh wlan show interfaces``。"""

    connected: bool = False
    ssid: str | None = None
    signal_pct: int | None = None
    channel: int | None = None
    band: str | None = None
    rx_mbps: float | None = None
    tx_mbps: float | None = None
    state: str | None = None
    interface: str | None = None


@dataclass(frozen=True)
class ChannelOccupancy:
    """周边 WiFi 信道占用。

    ``by_band`` 形如 ``{"2.4GHz": {6: 3, 11: 1}, "5GHz": {36: 2}}``。
    2.4G 与 5G 的同号信道互不干扰，**必须分开统计**，不能混在一起比数量。
    """

    by_band: dict[str, dict[int, int]] = field(default_factory=dict)
    current_channel: int | None = None
    current_band: str | None = None

    @property
    def empty(self) -> bool:
        return not any(self.by_band.values())

    def busiest(self, band: str | None = None) -> list[tuple[int, int]]:
        """返回 [(信道, 数量)]，按占用降序。未指定 band 时合并所有频段。"""
        if band is not None:
            counts = self.by_band.get(band, {})
        else:
            counts = {}
            for per_band in self.by_band.values():
                for ch, n in per_band.items():
                    counts[ch] = counts.get(ch, 0) + n
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
