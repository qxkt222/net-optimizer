# -*- coding: utf-8 -*-
"""系统写入命令拼装层测试（T4.2–T4.4 的基础设施）。

安全：所有命令都经由注入的 ``fake_run`` 执行；conftest 的 autouse 夹具会拦住
任何漏注入的真实调用。``netsh ... set/add`` / ``powercfg /set*`` / ``reg add``
在这里**只被断言 argv**，绝不真实执行，也不联网。

预期 argv 全部是按 v1 参数与需求书写**独立**的字面量，不从被测模块取值 ——
否则实现改了参数，测试会跟着一起错。
"""

from __future__ import annotations

import pytest

from netopt import platform as platform_mod
from netopt.platform import CmdResult
from netopt.system.commands import (
    flush_dns,
    query_power_settings,
    query_tcp_settings,
    set_dns_dhcp,
    set_dns_static,
    set_power_settings,
    set_tcp_settings,
    set_usb_selective_suspend,
)

_INTERFACE = "vEthernet (默认 交换机)"
_USB_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\USB"


def _dns_set(interface: str, server: str) -> list[str]:
    return [
        "netsh",
        "interface",
        "ipv4",
        "set",
        "dnsservers",
        f"name={interface}",
        "static",
        server,
        "primary",
    ]


def _dns_add(interface: str, server: str, index: int) -> list[str]:
    return [
        "netsh",
        "interface",
        "ipv4",
        "add",
        "dnsservers",
        f"name={interface}",
        server,
        f"index={index}",
    ]


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
def test_set_dns_static_builds_primary_then_indexed_adds(fake_run) -> None:
    run = fake_run({}, default="")
    servers = ["223.5.5.5", "119.29.29.29", "2400:3200::1"]

    results = set_dns_static(_INTERFACE, servers, run=run)

    assert run.calls == [
        _dns_set(_INTERFACE, "223.5.5.5"),
        _dns_add(_INTERFACE, "119.29.29.29", 2),
        _dns_add(_INTERFACE, "2400:3200::1", 3),
    ]
    assert [res.argv for res in results] == run.calls
    assert all(res.ok for res in results)


def test_set_dns_static_does_not_add_quotes_around_interface_name(fake_run) -> None:
    run = fake_run({}, default="")

    set_dns_static(_INTERFACE, ["223.5.5.5", "119.29.29.29"], run=run)

    for argv in run.calls:
        assert f"name={_INTERFACE}" in argv
        # 接口名作为单个 argv 元素传入，不得内嵌引号（实测会让 netsh 报语法错误）
        assert not any('"' in arg for arg in argv)


def test_set_dns_static_single_server_only_runs_set(fake_run) -> None:
    run = fake_run({}, default="")

    results = set_dns_static("以太网", ["223.5.5.5"], run=run)

    assert run.calls == [_dns_set("以太网", "223.5.5.5")]
    assert len(results) == 1


def test_set_dns_static_empty_servers_raises_and_runs_nothing(fake_run) -> None:
    run = fake_run({}, default="")

    with pytest.raises(ValueError, match="servers"):
        set_dns_static("以太网", [], run=run)

    assert run.calls == []


def test_set_dns_dhcp_argv(fake_run) -> None:
    run = fake_run({}, default="")

    result = set_dns_dhcp(_INTERFACE, run=run)

    assert run.calls == [
        [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            f"name={_INTERFACE}",
            "source=dhcp",
        ]
    ]
    assert result.ok


def test_flush_dns_argv(fake_run) -> None:
    run = fake_run({}, default="")

    result = flush_dns(run=run)

    assert run.calls == [["ipconfig", "/flushdns"]]
    assert result.ok


# ---------------------------------------------------------------------------
# TCP / 电源写入
# ---------------------------------------------------------------------------
def test_set_tcp_settings_runs_four_rules_in_order(fake_run) -> None:
    run = fake_run({}, default="")

    entries = set_tcp_settings(run=run)

    expected = [
        ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
        ["netsh", "int", "tcp", "set", "global", "ecncapability=disabled"],
        ["netsh", "int", "tcp", "set", "global", "rss=enabled"],
        ["netsh", "int", "tcp", "set", "global", "nonsackrttresiliency=disabled"],
    ]
    assert run.calls == expected
    assert [name for name, _ in entries] == [
        "TCP 窗口自动调优 (正常)",
        "禁用 ECN 显式拥塞通知 (兼容性)",
        "启用 RSS 接收方缩放",
        "关闭非对称延迟容忍 (提升稳定性)",
    ]
    assert [res.argv for _, res in entries] == expected
    assert all(res.ok for _, res in entries)
    # 每条规则恰好一次
    assert all(run.calls.count(argv) == 1 for argv in expected)


def test_set_power_settings_runs_three_rules_in_order(fake_run) -> None:
    run = fake_run({}, default="")

    entries = set_power_settings(run=run)

    wireless = "2a737441-1930-4402-8d77-b2bebba308a3"
    power = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
    expected = [
        ["powercfg", "/setacvalueindex", "SCHEME_CURRENT", wireless, power, "0"],
        ["powercfg", "/setdcvalueindex", "SCHEME_CURRENT", wireless, power, "0"],
        ["powercfg", "/setactive", "SCHEME_CURRENT"],
    ]
    assert run.calls == expected
    assert [name for name, _ in entries] == [
        "无线网卡节能 (交流电源)",
        "无线网卡节能 (直流电源)",
        "应用当前电源方案",
    ]
    assert [res.argv for _, res in entries] == expected
    assert all(res.ok for _, res in entries)
    assert all(run.calls.count(argv) == 1 for argv in expected)


@pytest.mark.parametrize(("enabled", "value"), [(False, "1"), (True, "0")])
def test_set_usb_selective_suspend_uses_inverted_registry_value(
    fake_run, enabled: bool, value: str
) -> None:
    run = fake_run({}, default="")

    result = set_usb_selective_suspend(enabled, run=run)

    assert run.calls == [
        [
            "reg",
            "add",
            _USB_KEY,
            "/v",
            "DisableSelectiveSuspend",
            "/t",
            "REG_DWORD",
            "/d",
            value,
            "/f",
        ]
    ]
    assert result.ok


def test_set_usb_selective_suspend_defaults_to_disabling(fake_run) -> None:
    run = fake_run({}, default="")

    set_usb_selective_suspend(run=run)

    assert run.calls[0][-2] == "1"


# ---------------------------------------------------------------------------
# 失败透传 / 依赖注入
# ---------------------------------------------------------------------------
def test_failure_result_is_returned_verbatim_not_swallowed(fake_run) -> None:
    denied = CmdResult(argv=[], code=5, out="拒绝访问")
    run = fake_run({("netsh", "interface", "ipv4", "add"): denied}, default=("", 0))

    results = set_dns_static("以太网", ["223.5.5.5", "119.29.29.29"], run=run)

    assert results[0].ok
    assert results[1] is denied
    assert results[1].code == 5
    assert not results[1].ok


def test_timeout_result_is_returned_verbatim(fake_run) -> None:
    timed_out = CmdResult(argv=[], code=-1, out="命令执行超时", timed_out=True)
    run = fake_run({("ipconfig",): timed_out})

    result = flush_dns(run=run)

    assert result is timed_out
    assert result.timed_out
    assert not result.ok


def test_default_runner_resolves_platform_run_at_call_time(monkeypatch) -> None:
    """``run=None`` 必须在调用时才取 ``platform.run``，否则测试无法替换。"""
    calls: list[list[str]] = []

    def _fake(argv, timeout=30.0):
        calls.append(list(argv))
        return CmdResult(argv=list(argv), code=0, out="")

    # conftest 已把 platform.run 换成陷阱函数；这里再换成记录器，
    # 只有「调用时才解析」的实现才能看到这次替换。
    monkeypatch.setattr(platform_mod, "run", _fake)

    result = flush_dns()

    assert calls == [["ipconfig", "/flushdns"]]
    assert result.ok


# ---------------------------------------------------------------------------
# 只读查询
# ---------------------------------------------------------------------------
def test_query_tcp_settings_is_read_only(fake_run) -> None:
    run = fake_run({("netsh",): "TCP 全局参数\n接收方缩放状态 : enabled"})

    entries = query_tcp_settings(run=run)

    assert run.calls == [["netsh", "int", "tcp", "show", "global"]]
    assert [name for name, _ in entries] == ["TCP 全局参数"]
    assert entries[0][1].out.startswith("TCP 全局参数")
    assert all("set" not in argv and "add" not in argv for argv in run.calls)


def test_query_power_settings_is_read_only(fake_run) -> None:
    run = fake_run(
        {
            ("powercfg", "/getactivescheme"): "电源方案 GUID: 6fecc5ae (Turbo)",
            ("powercfg", "/query"): "当前交流电源设置索引: 0x00000000",
            ("reg", "query"): "DisableSelectiveSuspend    REG_DWORD    0x1",
        }
    )

    entries = query_power_settings(run=run)

    wireless = "2a737441-1930-4402-8d77-b2bebba308a3"
    power = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
    assert run.calls == [
        ["powercfg", "/getactivescheme"],
        ["powercfg", "/query", "SCHEME_CURRENT", wireless, power],
        ["reg", "query", _USB_KEY, "/v", "DisableSelectiveSuspend"],
    ]
    assert [name for name, _ in entries] == [
        "当前电源方案",
        "无线网卡节能 (交流/直流)",
        "USB 选择性暂停",
    ]
    assert entries[0][1].out.startswith("电源方案 GUID")
    # 只读：不得出现任何写入型参数
    write_tokens = {"/setacvalueindex", "/setdcvalueindex", "/setactive", "add", "delete", "/f"}
    for argv in run.calls:
        assert not (set(argv) & write_tokens)
