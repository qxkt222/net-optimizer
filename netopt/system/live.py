# -*- coding: utf-8 -*-
"""SystemApi 的实机实现 —— 纯委托给 iphlpapi / wlanapi。

本模块只做组装，不缓存、不做业务判断：

- 平台信息 / 适配器 / 地址 / DNS / 路由 / 接口计数 → :mod:`netopt.system.iphlpapi`;
- WiFi 状态与周边扫描 → :mod:`netopt.system.wlanapi`。

两个 ctypes 模块都在**方法内部导入**：仅仅 ``import netopt.system.live``
不会加载任何 DLL，也不会因 DLL 缺失或非 Windows 环境在 import 阶段失败。
失败语义沿用底层实现：读不到数据抛 :class:`netopt.system.api.SystemUnavailable`，
本模块不吞异常、不把「读失败」改写成空列表。
"""

from __future__ import annotations

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

__all__ = ["LiveSystemApi"]


class LiveSystemApi:
    """SystemApi 的实机实现：iphlpapi + wlanapi。

    每次调用都重新读系统，因此拿到的是当时的快照；调用方不得依赖对象身份。
    """

    def platform_info(self) -> PlatformInfo:
        """返回 OS 版本、Python 版本、是否管理员与区域设置。"""
        from netopt.system import iphlpapi

        return iphlpapi.platform_info()

    def adapters(self) -> list[Adapter]:
        """返回所有网络适配器（含虚拟网卡与环回）。"""
        from netopt.system import iphlpapi

        return iphlpapi.adapters()

    def addresses(self) -> list[Address]:
        """返回所有适配器上的单播地址（IPv4 + IPv6）。"""
        from netopt.system import iphlpapi

        return iphlpapi.addresses()

    def dns_servers(self) -> list[InterfaceDns]:
        """返回每个接口的 DNS 服务器与来源（static / dhcp / none）。"""
        from netopt.system import iphlpapi

        return iphlpapi.dns_servers()

    def routes(self) -> list[Route]:
        """返回路由表（至少包含 IPv4 / IPv6 默认路由）。"""
        from netopt.system import iphlpapi

        return iphlpapi.routes()

    def if_stats(self) -> list[InterfaceStats]:
        """返回各接口的字节数、错误、丢弃与链路速率。"""
        from netopt.system import iphlpapi

        return iphlpapi.if_stats()

    def wifi(self) -> WifiState:
        """返回当前 WLAN 连接状态；有线环境下返回未连接。"""
        from netopt.system import wlanapi

        return wlanapi.wifi_state()

    def wifi_scan(self) -> WifiScan:
        """返回周边 WiFi 扫描结果；扫描不可用时由 ``WifiScan.error`` 说明。"""
        from netopt.system import wlanapi

        return wlanapi.wifi_scan()
