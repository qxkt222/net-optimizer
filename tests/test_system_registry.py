# -*- coding: utf-8 -*-
"""注册表 DNS 来源判定测试。

全部使用注入的假 ``key_open`` / ``query_value``：**不读本机真实注册表**，
不同机器、不同账号下真实值完全不同，依赖它会让测试随机失败。
"""

from __future__ import annotations

import winreg
from collections.abc import Callable

from netopt.domain.models import Adapter
from netopt.system.registry import dns_settings_for_adapters, read_dns_settings

_GUID = "{4F1A2B3C-1111-2222-3333-444455556666}"

KeyOpen = Callable[..., object]
QueryValue = Callable[..., tuple[object, int]]


class _FakeKey:
    """模拟 winreg 的 PyHKEY：支持 ``with`` 语句。"""

    def __init__(self, values: dict[str, object]) -> None:
        self.values = values
        self.closed = False

    def __enter__(self) -> _FakeKey:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self.closed = True
        return False


def _registry(
    values: dict[str, object], *, error: Exception | None = None
) -> tuple[KeyOpen, QueryValue, list[str]]:
    """造一对注入用的注册表操作，并记录被打开过的子键路径。"""
    opened: list[str] = []

    def key_open(hive: int, sub_key: str, *, access: int = 0) -> _FakeKey:
        opened.append(sub_key)
        if error is not None:
            raise error
        return _FakeKey(values)

    def query_value(key: _FakeKey, name: str) -> tuple[object, int]:
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], winreg.REG_SZ

    return key_open, query_value, opened


def _read(values: dict[str, object]) -> tuple[list[str], str]:
    key_open, query_value, _opened = _registry(values)
    return read_dns_settings(_GUID, key_open=key_open, query_value=query_value)


def test_static_name_server_comma_separated() -> None:
    assert _read({"NameServer": "8.8.8.8,1.1.1.1"}) == (
        ["8.8.8.8", "1.1.1.1"],
        "static",
    )


def test_static_name_server_space_separated() -> None:
    assert _read({"NameServer": "8.8.8.8 1.1.1.1"}) == (
        ["8.8.8.8", "1.1.1.1"],
        "static",
    )


def test_static_name_server_mixed_separators() -> None:
    assert _read({"NameServer": "8.8.8.8, 1.1.1.1  9.9.9.9"}) == (
        ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
        "static",
    )


def test_static_wins_over_dhcp() -> None:
    assert _read({"NameServer": "223.5.5.5", "DhcpNameServer": "192.0.2.1"}) == (
        ["223.5.5.5"],
        "static",
    )


def test_only_dhcp_name_server() -> None:
    assert _read({"DhcpNameServer": "192.0.2.1,192.0.2.2"}) == (
        ["192.0.2.1", "192.0.2.2"],
        "dhcp",
    )


def test_blank_static_value_falls_back_to_dhcp() -> None:
    assert _read({"NameServer": " ,  ", "DhcpNameServer": "192.0.2.1"}) == (
        ["192.0.2.1"],
        "dhcp",
    )


def test_no_values_returns_none() -> None:
    assert _read({}) == ([], "none")


def test_key_missing_returns_none() -> None:
    key_open, query_value, _opened = _registry({}, error=FileNotFoundError(_GUID))

    assert read_dns_settings(_GUID, key_open=key_open, query_value=query_value) == (
        [],
        "none",
    )


def test_key_permission_denied_returns_none() -> None:
    key_open, query_value, _opened = _registry({}, error=PermissionError("拒绝访问"))

    assert read_dns_settings(_GUID, key_open=key_open, query_value=query_value) == (
        [],
        "none",
    )


def test_value_permission_denied_returns_none() -> None:
    opened: list[str] = []

    def key_open(hive: int, sub_key: str, *, access: int = 0) -> _FakeKey:
        opened.append(sub_key)
        return _FakeKey({})

    def query_value(key: _FakeKey, name: str) -> tuple[object, int]:
        raise PermissionError(name)

    assert read_dns_settings(_GUID, key_open=key_open, query_value=query_value) == (
        [],
        "none",
    )


def test_ipv6_servers_are_preserved() -> None:
    assert _read({"NameServer": "2400:3200::1,2001:4860:4860::8888"}) == (
        ["2400:3200::1", "2001:4860:4860::8888"],
        "static",
    )


def test_duplicate_servers_are_removed_keeping_order() -> None:
    assert _read({"DhcpNameServer": "8.8.8.8,8.8.8.8 1.1.1.1 8.8.8.8"}) == (
        ["8.8.8.8", "1.1.1.1"],
        "dhcp",
    )


def test_interface_key_path_is_under_tcpip_interfaces() -> None:
    key_open, query_value, opened = _registry({})

    read_dns_settings(
        "4F1A2B3C-1111-2222-3333-444455556666", key_open=key_open, query_value=query_value
    )

    assert opened == [
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        rf"\{_GUID}"
    ]


def test_dns_settings_for_adapters_reads_by_guid_and_skips_missing_guid() -> None:
    guid_a = "4F1A2B3C-1111-2222-3333-444455556666"
    guid_b = "{AAAAAAAA-1111-2222-3333-444455556666}"
    values_by_guid: dict[str, dict[str, object]] = {
        guid_a: {"NameServer": "223.5.5.5"},
        "AAAAAAAA-1111-2222-3333-444455556666": {"DhcpNameServer": "192.0.2.1 192.0.2.2"},
    }

    def key_open(hive: int, sub_key: str, *, access: int = 0) -> _FakeKey:
        guid = sub_key.rsplit("\\", 1)[-1].strip("{}")
        return _FakeKey(values_by_guid.get(guid, {}))

    def query_value(key: _FakeKey, name: str) -> tuple[object, int]:
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], winreg.REG_SZ

    adapters = [
        Adapter(
            index=7,
            guid=guid_a,
            name="以太网",
            description="Intel Ethernet",
            mac=None,
            mtu=1500,
            connected=True,
        ),
        Adapter(
            index=9,
            guid=guid_b,
            name="WLAN",
            description="Intel Wi-Fi",
            mac=None,
            mtu=1500,
            connected=True,
            kind="wlan",
            is_primary=False,
        ),
        Adapter(
            index=11,
            guid=None,
            name="无 GUID 的接口",
            description="",
            mac=None,
            mtu=1500,
            connected=True,
        ),
        Adapter(
            index=13,
            guid="",
            name="空 GUID 的接口",
            description="",
            mac=None,
            mtu=1500,
            connected=True,
        ),
    ]

    settings = dns_settings_for_adapters(adapters, key_open=key_open, query_value=query_value)

    assert [item.adapter_index for item in settings] == [7, 9]
    assert settings[0].interface_name == "以太网"
    assert settings[0].servers == ["223.5.5.5"]
    assert settings[0].source == "static"
    assert settings[0].is_primary is True
    assert settings[1].interface_name == "WLAN"
    assert settings[1].servers == ["192.0.2.1", "192.0.2.2"]
    assert settings[1].source == "dhcp"
    assert settings[1].is_primary is False
