# -*- coding: utf-8 -*-
"""系统写入命令拼装层 —— 上层只描述意图，本模块负责拼 argv 并执行。

设计约束（BRIEF §3、``docs/SPEC.md`` §6.3 / §11）：

- **不打印、不读写备份、不做成败判断**：本模块只把「意图」翻译成 argv，交给
  注入的 runner 执行，原样返回 :class:`~netopt.platform.CmdResult`；是否重试、
  是否回滚、如何提示，全部由上层决定。
- ``run`` 默认在**调用时**解析为 :func:`netopt.platform.run`。不能写成 ``def``
  默认参数：那会在 import 时把函数对象绑死，测试和编排层都没法替换。
- 命令一律以 argv 列表传入、不经过 shell。接口名（可能含空格 / 中文）作为
  **单个** argv 元素传入 —— 实测 ``name=vEthernet (Default Switch)`` 这样 netsh
  能正确解析，自己加引号反而报语法错误。
"""

from __future__ import annotations

from netopt import platform
from netopt.platform import CmdResult, Runner

__all__ = [
    "flush_dns",
    "query_power_settings",
    "query_tcp_settings",
    "set_dns_dhcp",
    "set_dns_static",
    "set_power_settings",
    "set_tcp_settings",
    "set_usb_selective_suspend",
]

#: 无线网卡节能的子组 GUID 与设置 GUID（与 v1 一致）。
_WIRELESS_GUID = "2a737441-1930-4402-8d77-b2bebba308a3"
_POWER_GUID = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
#: USB 选择性暂停所在的注册表键。
_USB_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\USB"


def _resolve(run: Runner | None) -> Runner:
    """在**调用时**解析可注入依赖（BRIEF §3：不能写成 def 默认参数）。"""
    return run if run is not None else platform.run


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
def set_dns_static(
    interface: str, servers: list[str], *, run: Runner | None = None
) -> list[CmdResult]:
    """把接口的 DNS 设为给定静态地址，按列表顺序逐条执行并返回每次结果。

    - 第一个服务器 → ``set dnsservers name=<接口> static <ip> primary``；
    - 其余服务器 → ``add dnsservers name=<接口> <ip> index=n``（n 从 2 开始）。

    ``servers`` 为空时抛 :class:`ValueError`：没有地址就表达不了「设为静态
    DNS」的意图，静默返回空列表会让上层误以为已改好。这里**不短路、不判断
    成败**，即使某条失败也会把剩余命令执行完并如实返回，汇总由上层负责。
    """
    if not servers:
        raise ValueError("servers 不能为空：至少需要一个 DNS 服务器地址")
    runner = _resolve(run)
    results = [
        runner(
            [
                "netsh",
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                f"name={interface}",
                "static",
                servers[0],
                "primary",
            ]
        )
    ]
    for index, server in enumerate(servers[1:], start=2):
        results.append(
            runner(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "add",
                    "dnsservers",
                    f"name={interface}",
                    server,
                    f"index={index}",
                ]
            )
        )
    return results


def set_dns_dhcp(interface: str, *, run: Runner | None = None) -> CmdResult:
    """把接口的 DNS 来源改回 DHCP，返回执行结果。"""
    runner = _resolve(run)
    return runner(
        ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={interface}", "source=dhcp"]
    )


def flush_dns(*, run: Runner | None = None) -> CmdResult:
    """清空本机 DNS 缓存（``ipconfig /flushdns``），返回执行结果。"""
    runner = _resolve(run)
    return runner(["ipconfig", "/flushdns"])


# ---------------------------------------------------------------------------
# TCP / 电源
# ---------------------------------------------------------------------------
def set_tcp_settings(*, run: Runner | None = None) -> list[tuple[str, CmdResult]]:
    """按 v1 的四条规则调整 TCP 全局参数，返回 ``[(中文说明, 结果), ...]``。

    顺序固定为：窗口自动调优 → 禁用 ECN → 启用 RSS → 关闭非对称延迟容忍。
    每条规则只执行一次，失败也继续执行后面的规则。
    """
    runner = _resolve(run)
    rules = [
        (
            "TCP 窗口自动调优 (正常)",
            ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
        ),
        (
            "禁用 ECN 显式拥塞通知 (兼容性)",
            ["netsh", "int", "tcp", "set", "global", "ecncapability=disabled"],
        ),
        ("启用 RSS 接收方缩放", ["netsh", "int", "tcp", "set", "global", "rss=enabled"]),
        (
            "关闭非对称延迟容忍 (提升稳定性)",
            ["netsh", "int", "tcp", "set", "global", "nonsackrttresiliency=disabled"],
        ),
    ]
    return [(name, runner(argv)) for name, argv in rules]


def set_power_settings(*, run: Runner | None = None) -> list[tuple[str, CmdResult]]:
    """禁用无线网卡节能并应用当前电源方案，返回 ``[(中文说明, 结果), ...]``。

    三条命令与 v1 一致：交流电源索引置 0、直流电源索引置 0、最后 ``setactive``
    让方案重新生效。顺序不可换 —— ``setacvalueindex`` / ``setdcvalueindex``
    只改方案存储，必须再 ``setactive`` 才会实际生效。
    """
    runner = _resolve(run)
    rules = [
        (
            "无线网卡节能 (交流电源)",
            ["powercfg", "/setacvalueindex", "SCHEME_CURRENT", _WIRELESS_GUID, _POWER_GUID, "0"],
        ),
        (
            "无线网卡节能 (直流电源)",
            ["powercfg", "/setdcvalueindex", "SCHEME_CURRENT", _WIRELESS_GUID, _POWER_GUID, "0"],
        ),
        ("应用当前电源方案", ["powercfg", "/setactive", "SCHEME_CURRENT"]),
    ]
    return [(name, runner(argv)) for name, argv in rules]


def set_usb_selective_suspend(enabled: bool = False, *, run: Runner | None = None) -> CmdResult:
    """设置 USB 选择性暂停，返回执行结果。

    注意参数语义与注册表值**相反**：``enabled=True`` 表示允许选择性暂停，
    写入 ``DisableSelectiveSuspend=0``；默认 ``enabled=False``（禁用暂停、
    防止 USB 网卡休眠）写入 ``1``，与 v1 ``fix power`` 的行为一致。
    """
    runner = _resolve(run)
    value = "0" if enabled else "1"
    return runner(
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
    )


# ---------------------------------------------------------------------------
# 只读查询（供上层在修改前记录原值）
# ---------------------------------------------------------------------------
def query_tcp_settings(*, run: Runner | None = None) -> list[tuple[str, CmdResult]]:
    """只读查询 TCP 全局参数，返回 ``[("TCP 全局参数", 结果)]``。

    ``netsh int tcp show global`` 一次返回全部项，输出是给人看的对齐文本而非
    结构化字段；本模块原样返回，解析交给上层，**不在这里编造字段**。
    """
    runner = _resolve(run)
    return [("TCP 全局参数", runner(["netsh", "int", "tcp", "show", "global"]))]


def query_power_settings(*, run: Runner | None = None) -> list[tuple[str, CmdResult]]:
    """只读查询电源相关原值，供上层在修改前记录（journal 的 ``before``）。

    返回三项：

    - 当前电源方案：``powercfg /getactivescheme``；
    - 无线网卡节能的交流/直流索引：
      ``powercfg /query SCHEME_CURRENT <子组 GUID> <设置 GUID>``。
      实测 ``powercfg /query SCHEME_CURRENT SUB_NONE`` 只回显方案 GUID，拿不到
      无线节能项，因此改用等价的只读 GUID 查询 —— 它能直接给出
      ``当前交流电源设置索引`` / ``当前直流电源设置索引``；
    - USB 选择性暂停的注册表值：``reg query``。:func:`set_usb_selective_suspend`
      改的是注册表，回滚同样需要原值。
    """
    runner = _resolve(run)
    entries = [
        ("当前电源方案", ["powercfg", "/getactivescheme"]),
        (
            "无线网卡节能 (交流/直流)",
            ["powercfg", "/query", "SCHEME_CURRENT", _WIRELESS_GUID, _POWER_GUID],
        ),
        ("USB 选择性暂停", ["reg", "query", _USB_KEY, "/v", "DisableSelectiveSuspend"]),
    ]
    return [(name, runner(argv)) for name, argv in entries]
