# -*- coding: utf-8 -*-
r"""Windows 注册表 DNS 来源判定 —— static / dhcp / none。

读路径是**只读**的，不写任何值：打开
``HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}``，
读两个 REG_SZ：

- ``NameServer``：手工配置的静态服务器（逗号或空格分隔，可混 IPv4/IPv6）；
- ``DhcpNameServer``：从 DHCP 服务器拿到的服务器。

判定规则与 netsh 的「静态 / 由 DHCP 分配」一致：``NameServer`` 非空 → ``static``；
否则 ``DhcpNameServer`` 非空 → ``dhcp``；都没有 → ``none``。

注册表项不存在、无权限或其他读取失败一律返回 ``([], "none")``,
**本模块不向调用方抛系统异常** —— 读不到就当「来源未知」，由上层决定怎么呈现。

``key_open`` / ``query_value`` 可注入：测试必须用假实现，不要依赖本机真实
注册表内容（不同机器、不同账号权限下结果完全不同）。
"""

from __future__ import annotations

import re
import winreg
from collections.abc import Callable, Iterable
from typing import Any

from netopt.domain.models import Adapter, InterfaceDns

#: 接口注册表项的父键（相对 ``HKEY_LOCAL_MACHINE``）。
_INTERFACES_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"

#: 静态配置的 DNS 服务器值名。
_STATIC_VALUE = "NameServer"

#: DHCP 下发的 DNS 服务器值名。
_DHCP_VALUE = "DhcpNameServer"

#: 服务器列表可能用逗号、空格或混排分隔。
_SERVERS_SEP = re.compile(r"[,\s]+")

#: 可注入的注册表操作类型（真实实现分别是 ``winreg.OpenKey`` / ``winreg.QueryValueEx``）。
KeyOpen = Callable[..., Any]
QueryValue = Callable[..., Any]


def read_dns_settings(
    guid: str,
    *,
    key_open: KeyOpen = winreg.OpenKey,
    query_value: QueryValue = winreg.QueryValueEx,
) -> tuple[list[str], str]:
    """读取一个接口 GUID 的 DNS 服务器与来源。

    参数 ``guid`` 带不带大括号都可以，内部统一规范化成 ``{GUID}``。

    返回 ``(servers, source)``：``servers`` 去重且保持注册表里的顺序，
    IPv4 / IPv6 原样保留；``source`` 是 ``static`` / ``dhcp`` / ``none``。

    键不存在（``FileNotFoundError``）、无权限（``PermissionError``）以及
    其他注册表读取错误都返回 ``([], "none")``，不抛异常。
    """
    sub_key = _interface_key_path(guid)
    dhcp_servers: list[str] = []
    try:
        with key_open(winreg.HKEY_LOCAL_MACHINE, sub_key, access=winreg.KEY_READ) as key:
            static_servers = _parse_servers(_read_string(key, _STATIC_VALUE, query_value))
            if static_servers:
                return static_servers, "static"
            dhcp_servers = _parse_servers(_read_string(key, _DHCP_VALUE, query_value))
    except OSError:
        # 键不存在 / 无权限 / 其他读取失败：一律按「不知道」处理。
        return [], "none"

    if dhcp_servers:
        return dhcp_servers, "dhcp"
    return [], "none"


def dns_settings_for_adapters(
    adapters: Iterable[Adapter],
    *,
    key_open: KeyOpen = winreg.OpenKey,
    query_value: QueryValue = winreg.QueryValueEx,
) -> list[InterfaceDns]:
    """按 ``Adapter.guid`` 批量读取 DNS 来源。

    ``guid`` 为 ``None``（或空串）的适配器直接跳过 —— 没有 GUID 就无法定位
    注册表项，硬查只会得到「不存在」。返回顺序与传入顺序一致。
    """
    settings: list[InterfaceDns] = []
    for adapter in adapters:
        guid = adapter.guid
        if not guid:
            continue
        servers, source = read_dns_settings(guid, key_open=key_open, query_value=query_value)
        settings.append(
            InterfaceDns(
                adapter_index=adapter.index,
                interface_name=adapter.name,
                servers=servers,
                source=source,
                is_primary=adapter.is_primary,
            )
        )
    return settings


def _interface_key_path(guid: str) -> str:
    """把 GUID 规范化成注册表子键路径（统一带大括号）。"""
    normalized = guid.strip().strip("{}")
    return f"{_INTERFACES_KEY}\\{{{normalized}}}"


def _read_string(key: Any, name: str, query_value: QueryValue) -> str | None:
    """读一个字符串值；值不存在或为空时返回 ``None``。"""
    try:
        value, _kind = query_value(key, name)
    except OSError:
        return None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_servers(raw: str | None) -> list[str]:
    """按逗号/空格拆分服务器列表，去空、去重并保持首次出现顺序。"""
    if not raw:
        return []
    servers: list[str] = []
    seen: set[str] = set()
    for token in _SERVERS_SEP.split(raw):
        token = token.strip()
        if not token or token in seen:
            continue
        seen.add(token)
        servers.append(token)
    return servers


__all__ = ["dns_settings_for_adapters", "read_dns_settings"]
