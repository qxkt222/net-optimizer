# -*- coding: utf-8 -*-
"""修复编排 —— ``fix dns/tcp/power`` 与 ``auto`` 一键优化。

本模块只做「编排」：探测走 :mod:`netopt.probes`，执行走**注入的** ``run``
（默认在调用时才解析为 :func:`netopt.platform.run`），渲染走 :mod:`netopt.ui`。
测试一律通过 ``run=fake_run(...)`` 注入假 runner，绝不真实执行会修改系统的命令。

CLI 契约：``fix dns --restore`` → ``cmd_fix("dns", restore=True)``；
其余 ``fix dns/tcp/power/all`` → ``cmd_fix(what)``。

缺陷修复点：

- **D5**：``cmp_tag`` 旧写法 ``if delta <= 1`` 把负数也吞了，``elif delta < 0``
  是死代码，改善永远显示「(稳定)」；现在 ``abs(delta) <= 1`` 才算稳定，
  下降显示 ↓（改善）、上升显示 ↑（变差）。
- **D11**：``fix dns`` **只动承载默认路由的接口**
  （:func:`netopt.probes.primary_interfaces`），修改前先把原名值
  （``servers`` + ``source``）落盘到 :data:`netopt.state.DNS_BACKUP_FILE`，
  并新增 :func:`restore_dns`（``fix dns --restore``）按 ``source`` 还原。
- **D9**：失败提示不再撒谎 —— :class:`~netopt.platform.CmdResult` 区分
  「超时」与「命令不存在」，:func:`_fail_detail` 如实分别显示。
- **D14**：本模块不含任何清除逻辑，CLI/GUI 需要时直接调
  :func:`netopt.state.clear`；提权统一走 :func:`netopt.platform.elevate`。
"""

from __future__ import annotations

import json
import time

from netopt import platform, probes, state, ui
from netopt.models import PingStat
from netopt.platform import CmdResult, Runner

__all__ = [
    "PRIMARY_DNS",
    "SECONDARY_DNS",
    "cmd_auto",
    "cmd_fix",
    "cmp_tag",
    "fix_dns",
    "fix_power",
    "fix_tcp",
    "load_dns_backup",
    "restore_dns",
]

PRIMARY_DNS = "223.5.5.5"
SECONDARY_DNS = "119.29.29.29"

# 无线网卡节能模式 (禁用省电, 解决掉线/卡顿)
_WIRELESS_GUID = "2a737441-1930-4402-8d77-b2bebba308a3"
_POWER_GUID = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"


def _resolve(run: Runner | None) -> Runner:
    """在**调用时**解析可注入依赖（BRIEF §5：不能写成 def 默认参数）。"""
    return run if run is not None else platform.run


def _step(ok: bool, name: str, detail: str = "") -> bool:
    tag = ui.green("✓ 完成") if ok else ui.red("✗ 失败")
    print(f"  {tag}  {name}" + (f"  {ui.yellow(detail)}" if detail else ""))
    return ok


def _fail_detail(res: CmdResult) -> str:
    """把失败原因如实转成提示（D9：超时 ≠ 命令不存在）。"""
    if res.timed_out:
        return "(命令执行超时)"
    if res.missing:
        return "(系统不支持, 已跳过)"
    text = " ".join(res.out.split())
    if text:
        return f"(失败: {text[:60]})"
    return f"(失败, 退出码 {res.code})"


# ---------------------------------------------------------------------------
# DNS 备份（D11）：接口名 -> {servers, source, time}
# ---------------------------------------------------------------------------
def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def load_dns_backup() -> dict:
    """读取 DNS 备份；文件缺失 / 损坏 / 结构不对时返回 ``{}``。"""
    try:
        with open(state.DNS_BACKUP_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("interfaces"), dict):
        return {}
    data["interfaces"] = {
        name: entry
        for name, entry in data["interfaces"].items()
        if isinstance(name, str) and isinstance(entry, dict)
    }
    return data


def _save_dns_backup(entries: dict[str, dict]) -> bool:
    """把 ``{接口名: {servers, source, time}}`` 落盘；失败返回 False。"""
    try:
        with open(state.DNS_BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump({"created": _now(), "interfaces": entries}, f, ensure_ascii=False, indent=1)
        return True
    except OSError:
        return False


def _merge_backup(existing: dict, fresh: dict[str, dict]) -> dict[str, dict]:
    """合并备份：**已有记录优先**。

    重复执行 ``fix dns`` 时，备份里应保留最早的原值而不是上一次已被改过的值，
    否则「还原」会把 DNS 还原成 ``223.5.5.5`` 自己。
    """
    merged: dict[str, dict] = dict(fresh)
    merged.update(existing)
    return merged


def fix_dns(run: Runner | None = None, *, restore: bool = False) -> bool:
    """备份并按需修复 DNS（D11）。

    - 只处理 :func:`netopt.probes.primary_interfaces`（承载默认路由的接口）；
    - **发出任何修改命令之前**先把原值写进 :data:`netopt.state.DNS_BACKUP_FILE`，
      备份失败则中止，不做任何修改；
    - 目标 DNS 已是 ``223.5.5.5 / 119.29.29.29`` 时跳过设置（幂等），但仍会备份；
    - ``restore=True`` 时改调 :func:`restore_dns`。
    """
    run = _resolve(run)
    if restore:
        return restore_dns(run=run)

    print(ui.bold("== 修复 DNS =="))
    targets = probes.primary_interfaces(run=run)
    if not targets:
        return _step(False, "未找到承载默认路由的接口", "已跳过 DNS 修改")

    current = {cfg.interface: cfg for cfg in probes.dns_config(run=run)}
    unreadable = [iface.name for iface in targets if iface.name not in current]
    if unreadable:
        names = ", ".join(unreadable)
        return _step(False, f"无法读取接口 [{names}] 的当前 DNS", "已中止, 未做任何修改")

    fresh = {
        iface.name: {
            "servers": list(current[iface.name].servers),
            "source": current[iface.name].source,
            "time": _now(),
        }
        for iface in targets
    }
    merged = _merge_backup(load_dns_backup().get("interfaces", {}), fresh)
    if not _save_dns_backup(merged):
        detail = f"{state.DNS_BACKUP_FILE} (已中止, 未做任何修改)"
        return _step(False, "无法写入 DNS 备份文件", detail)
    _step(True, f"已备份 {len(fresh)} 个接口的 DNS 原值", str(state.DNS_BACKUP_FILE))

    flush = run(["ipconfig", "/flushdns"])
    _step(flush.ok, "清除 DNS 缓存", "" if flush.ok else _fail_detail(flush))

    all_ok = True
    for iface in targets:
        step_name = f"接口 [{iface.name}] 设置 DNS: {PRIMARY_DNS} / {SECONDARY_DNS}"
        if set(current[iface.name].servers) == {PRIMARY_DNS, SECONDARY_DNS}:
            _step(True, step_name, "(已是目标 DNS, 跳过)")
            continue
        first = run(
            [
                "netsh",
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                f"name={iface.name}",
                "static",
                PRIMARY_DNS,
                "primary",
            ]
        )
        if not first.ok:
            all_ok = _step(False, step_name, _fail_detail(first)) and all_ok
            continue
        second = run(
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "dnsservers",
                f"name={iface.name}",
                SECONDARY_DNS,
                "index=2",
            ]
        )
        all_ok = _step(second.ok, step_name, "" if second.ok else _fail_detail(second)) and all_ok
    return all_ok


def restore_dns(run: Runner | None = None) -> bool:
    """按备份还原 DNS（D11 新增能力），逐接口报告成功与否。

    - ``static`` 且备份里有地址 → ``set dnsservers ... static <第一个> primary``，
      其余地址依次 ``add dnsservers ... index=n``（n 从 2 开始）；
    - ``dhcp`` / ``none``（或 static 却没有地址）→ ``set dnsservers ... source=dhcp``；
    - 没有备份文件时明确提示「没有可还原的备份」并返回 False，不静默成功。
    """
    run = _resolve(run)
    print(ui.bold("== 还原 DNS =="))
    entries = load_dns_backup().get("interfaces", {})
    if not entries:
        print(ui.yellow("  没有可还原的备份 (先运行一次 fix dns 才会生成备份)"))
        return False

    all_ok = True
    for name, entry in entries.items():
        raw_servers = entry.get("servers")
        servers = (
            [s for s in raw_servers if isinstance(s, str)] if isinstance(raw_servers, list) else []
        )
        source = entry.get("source")
        if source == "static" and servers:
            step_name = f"接口 [{name}] 还原静态 DNS: {' / '.join(servers)}"
            first = run(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    f"name={name}",
                    "static",
                    servers[0],
                    "primary",
                ]
            )
            if not first.ok:
                all_ok = _step(False, step_name, _fail_detail(first)) and all_ok
                continue
            ok, detail = True, ""
            for index, addr in enumerate(servers[1:], start=2):
                res = run(
                    [
                        "netsh",
                        "interface",
                        "ipv4",
                        "add",
                        "dnsservers",
                        f"name={name}",
                        addr,
                        f"index={index}",
                    ]
                )
                if not res.ok:
                    ok, detail = False, _fail_detail(res)
                    break
            all_ok = _step(ok, step_name, detail) and all_ok
        else:
            step_name = f"接口 [{name}] 还原为 DHCP"
            res = run(
                ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "source=dhcp"]
            )
            all_ok = _step(res.ok, step_name, "" if res.ok else _fail_detail(res)) and all_ok
    return all_ok


# ---------------------------------------------------------------------------
# TCP / 电源
# ---------------------------------------------------------------------------
def fix_tcp(run: Runner | None = None) -> bool:
    """修复 TCP 栈：4 条 netsh 规则（参数与旧实现一致）。"""
    run = _resolve(run)
    print(ui.bold("== 修复 TCP 栈 =="))
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
    all_ok = True
    for name, cmd in rules:
        res = run(cmd)
        all_ok = _step(res.ok, name, "" if res.ok else _fail_detail(res)) and all_ok
    return all_ok


def fix_power(run: Runner | None = None) -> bool:
    """禁用无线网卡节能与 USB 选择性暂停（参数与旧实现一致）。"""
    run = _resolve(run)
    print(ui.bold("== 修复电源节能 =="))
    power_cmds = [
        [
            "powercfg",
            "/setacvalueindex",
            "SCHEME_CURRENT",
            _WIRELESS_GUID,
            _POWER_GUID,
            "0",
        ],
        [
            "powercfg",
            "/setdcvalueindex",
            "SCHEME_CURRENT",
            _WIRELESS_GUID,
            _POWER_GUID,
            "0",
        ],
        ["powercfg", "/setactive", "SCHEME_CURRENT"],
    ]
    results = [run(cmd) for cmd in power_cmds]
    failed = next((res for res in results if not res.ok), None)
    detail = "" if failed is None else _fail_detail(failed)
    all_ok = _step(failed is None, "禁用无线网卡节能 (电源模式)", detail)

    reg = run(
        [
            "reg",
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Services\USB",
            "/v",
            "DisableSelectiveSuspend",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ]
    )
    usb_ok = _step(
        reg.ok, "禁用 USB 选择性暂停 (防止 USB 网卡休眠)", "" if reg.ok else _fail_detail(reg)
    )
    return all_ok and usb_ok


# ---------------------------------------------------------------------------
# 命令入口
# ---------------------------------------------------------------------------
def cmd_fix(what: str = "all", *, restore: bool = False, run: Runner | None = None) -> bool:
    """``fix dns/tcp/power/all`` 入口；``restore=True``（``fix dns --restore``）只对 dns 有效。"""
    run = _resolve(run)
    if what not in ("dns", "tcp", "power", "all"):
        print(ui.red(f"未知修复项: {what} (可选 dns/tcp/power/all)"))
        return False
    if restore and what != "dns":
        print(ui.red("--restore 只能与 fix dns 一起使用"))
        return False

    ok = True
    if what in ("dns", "all"):
        ok = fix_dns(run=run, restore=restore) and ok
    if restore:
        state.log(f"fix dns 还原{'成功' if ok else '失败'}")
        return ok
    if what in ("tcp", "all"):
        print()
        ok = fix_tcp(run=run) and ok
    if what in ("power", "all"):
        print()
        ok = fix_power(run=run) and ok
    print()
    print(ui.bold("提示: TCP 修复需重启部分生效; 若仍卡顿可尝试重启路由器"))
    state.log(f"fix {what} 完成")
    return ok


def cmp_tag(desc: str, before: float | None, after: float | None, unit: str = "ms") -> str:
    """复测对比行（D5）。

    旧实现 ``if delta <= 1`` 把所有负数也判成「稳定」，``elif delta < 0`` 是死代码
    （实测 40→20、40→10 全报「(稳定)」）。现在 ``abs(delta) <= 1`` 才是稳定，
    下降显示 ↓（改善）、上升显示 ↑（变差）。
    """
    if before is None or after is None:
        return f"  {desc}: {ui.yellow('-')}"
    delta = after - before
    if abs(delta) <= 1:
        tag = ui.green(f"{after:.0f} {unit} (稳定)")
    elif delta < 0:
        tag = ui.green(f"{after:.0f} {unit} (↓{abs(delta):.0f})")
    else:
        tag = ui.red(f"{after:.0f} {unit} (↑{delta:.0f})")
    return f"  {desc}: {before:.0f} → {tag}"


def _measure(run: Runner) -> tuple[PingStat, PingStat, float | None]:
    """auto 用：返回 (网关统计, 百度统计, DNS 解析耗时毫秒或 None)。"""
    gw = probes.gateway(run=run)
    if gw is not None:
        gateway_stat = probes.ping(gw.ip, count=4, run=run)
    else:
        gateway_stat = PingStat(target="(无默认网关)", loss_pct=100.0, replies=0)
    baidu_stat = probes.ping("www.baidu.com", count=4, run=run)
    return gateway_stat, baidu_stat, probes.dns_query(PRIMARY_DNS, "www.baidu.com")


def cmd_auto(run: Runner | None = None) -> bool:
    """一键优化：诊断 → 自动修复 → 复测对比（非管理员时走 platform.elevate）。"""
    run = _resolve(run)
    print(ui.bold("== 一键优化: 诊断 → 自动修复 → 复测 =="))
    print(ui.bold("── 第 1 步: 诊断 ──"))
    g, b, d = _measure(run)
    problems: list[str] = []
    if g.avg_ms is None:
        print(ui.red("  网关不可达 — 请先检查路由器/WiFi 连接"))
        problems.append("网关不可达")
    else:
        print(f"  网关延迟 {g.avg_ms:.0f} ms, 丢包 {g.loss_pct:.0f}%")
        if g.loss_pct > 0:
            problems.append("网关丢包")
    if b.avg_ms is None:
        print(ui.red("  百度不可达"))
        problems.append("外网不可达")
    else:
        print(f"  百度延迟 {b.avg_ms:.0f} ms, 丢包 {b.loss_pct:.0f}%")
        if b.loss_pct > 0:
            problems.append("外网丢包")
        elif b.avg_ms > 60:
            problems.append("外网延迟偏高")
    if d is None:
        print(ui.red("  DNS 解析失败"))
        problems.append("DNS 异常")
    else:
        print(f"  DNS 解析 {d:.0f} ms")
        if d > 100:
            problems.append("DNS 解析慢")

    if not problems:
        print(ui.green("\n  未发现明显问题, 仍会做一轮预防性优化"))
    else:
        print(ui.yellow(f"\n  发现问题: {'、'.join(problems)}"))

    print(ui.bold("\n── 第 2 步: 自动修复 (需要管理员权限) ──"))
    if not platform.is_admin():
        print(ui.yellow("  当前非管理员, 正在以管理员身份重新启动..."))
        platform.elevate(["auto", "--wait"])
        return False
    ok = fix_dns(run=run)
    print()
    ok = fix_tcp(run=run) and ok
    print()
    ok = fix_power(run=run) and ok

    print(ui.bold("\n── 第 3 步: 复测 ──"))
    g2, b2, d2 = _measure(run)
    print(cmp_tag("网关延迟", g.avg_ms, g2.avg_ms))
    print(cmp_tag("百度延迟", b.avg_ms, b2.avg_ms))
    print(cmp_tag("DNS 解析", d, d2))

    print(ui.bold("\n── 优化建议 ──"))
    if b2.avg_ms is not None and b2.avg_ms > 60:
        print(ui.yellow("  · 外网延迟仍偏高: 宽带高峰期常见, 可尝试重启路由器/光猫"))
    if g2.avg_ms is not None and g2.avg_ms > 10:
        print(ui.yellow("  · 网关延迟偏高: 检查 WiFi 信号或改用 5GHz 频段 (运行 'wifi' 查看)"))
    print(ui.green("  · 建议每周运行一次 'auto' 保持最佳状态"))
    baidu = f"{b2.avg_ms:.0f}" if b2.avg_ms is not None else "-"
    state.log(f"auto 完成: 百度 {baidu}ms 丢包 {b2.loss_pct:.0f}%")
    return ok
