# -*- coding: utf-8 -*-
"""系统访问层接口 —— 上层只依赖这里，不直接碰 ctypes / winreg。

v2 的读路径统一走 :class:`SystemApi`：真实实现（``LiveSystemApi``，下一批交付）
用 ctypes 调 iphlpapi / wlanapi，注册表读 DNS 来源走
:mod:`netopt.system.registry`；测试用 :class:`FakeSystemApi` 构造任意系统状态。

**失败语义**：任何方法读不到数据都应抛 :class:`SystemUnavailable`（带一句中文
原因），由 probe 转成 ``ProbeError``。**不得**静默返回空列表 —— v1 的
``if res.missing: return []`` 会把「API 不可用」伪装成「这台机器没有网卡」。
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from typing import Protocol, runtime_checkable

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


class SystemUnavailable(RuntimeError):
    """某个系统 API 在此机器/此版本上不可用。

    消息里必须写清是哪项能力、为什么不可用（例如 DLL 缺失、调用返回错误码、
    权限不足），供 probe 原样转进 ``ProbeError.message``。
    """


@runtime_checkable
class SystemApi(Protocol):
    """读系统网络状态的唯一入口。

    每个方法返回的都是一份快照：实现方可以每次重新读取，调用方不得依赖
    对象身份。读失败一律抛 :class:`SystemUnavailable`，不要返回空列表冒充
    「没有数据」。
    """

    def platform_info(self) -> PlatformInfo:
        """返回 OS 版本、Python 版本、是否管理员、区域设置。"""
        ...

    def adapters(self) -> list[Adapter]:
        """返回所有网络适配器（含虚拟网卡与环回）。"""
        ...

    def addresses(self) -> list[Address]:
        """返回所有适配器上的单播地址（IPv4 + IPv6）。"""
        ...

    def dns_servers(self) -> list[InterfaceDns]:
        """返回每个接口的 DNS 服务器与来源（static / dhcp / none）。"""
        ...

    def routes(self) -> list[Route]:
        """返回路由表（至少包含 IPv4 / IPv6 默认路由）。"""
        ...

    def if_stats(self) -> list[InterfaceStats]:
        """返回各接口的字节数、错误、丢弃与链路速率。"""
        ...

    def wifi(self) -> WifiState:
        """返回当前 WLAN 连接状态；有线环境下应返回未连接。"""
        ...

    def wifi_scan(self) -> WifiScan:
        """返回周边 WiFi 扫描结果；扫描不可用时通过 ``WifiScan.error`` 说明。"""
        ...


class FakeSystemApi:
    """测试替身：按构造参数返回固定快照，每次调用都返回深拷贝。

    默认全部为空：无适配器、无地址、无 DNS、无路由、无统计，WiFi 未连接、
    扫描无结果。参数名与协议方法一一对应，测试里只覆盖关心的那几项即可。

    深拷贝是刻意的：真实实现每次读系统都会得到新对象，Fake 也保持同样的
    语义，免得调用方误以为可以就地修改返回的列表（``InterfaceDns.servers``
    这类字段内部还嵌着可变列表）。
    """

    def __init__(
        self,
        *,
        platform_info: PlatformInfo | None = None,
        adapters: Iterable[Adapter] = (),
        addresses: Iterable[Address] = (),
        dns_servers: Iterable[InterfaceDns] = (),
        routes: Iterable[Route] = (),
        if_stats: Iterable[InterfaceStats] = (),
        wifi: WifiState | None = None,
        wifi_scan: WifiScan | None = None,
    ) -> None:
        self._platform_info = PlatformInfo() if platform_info is None else platform_info
        self._adapters = list(adapters)
        self._addresses = list(addresses)
        self._dns_servers = list(dns_servers)
        self._routes = list(routes)
        self._if_stats = list(if_stats)
        self._wifi = WifiState() if wifi is None else wifi
        self._wifi_scan = WifiScan() if wifi_scan is None else wifi_scan

    def platform_info(self) -> PlatformInfo:
        """返回构造时给定的平台信息。"""
        return copy.deepcopy(self._platform_info)

    def adapters(self) -> list[Adapter]:
        """返回构造时给定的适配器列表的副本。"""
        return copy.deepcopy(self._adapters)

    def addresses(self) -> list[Address]:
        """返回构造时给定的地址列表的副本。"""
        return copy.deepcopy(self._addresses)

    def dns_servers(self) -> list[InterfaceDns]:
        """返回构造时给定的 DNS 配置列表的副本。"""
        return copy.deepcopy(self._dns_servers)

    def routes(self) -> list[Route]:
        """返回构造时给定的路由列表的副本。"""
        return copy.deepcopy(self._routes)

    def if_stats(self) -> list[InterfaceStats]:
        """返回构造时给定的接口统计列表的副本。"""
        return copy.deepcopy(self._if_stats)

    def wifi(self) -> WifiState:
        """返回构造时给定的 WLAN 状态。"""
        return copy.deepcopy(self._wifi)

    def wifi_scan(self) -> WifiScan:
        """返回构造时给定的扫描结果。"""
        return copy.deepcopy(self._wifi_scan)


__all__ = ["FakeSystemApi", "SystemApi", "SystemUnavailable"]
