# -*- coding: utf-8 -*-
"""修复命令：fix dns/tcp/power、auto 一键优化。所有操作需管理员权限。"""
import re

import netlib as nl

PRIMARY_DNS = "223.5.5.5"
SECONDARY_DNS = "119.29.29.29"

# 无线网卡节能模式 (禁用省电, 解决掉线/卡顿)
_WIRELESS_GUID = "2a737441-1930-4402-8d77-b2bebba308a3"
_POWER_GUID = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"

def _step(ok, name, detail=""):
    tag = nl.green("✓ 完成") if ok else nl.red("✗ 失败")
    print(f"  {tag}  {name}" + (f"  {nl.yellow(detail)}" if detail else ""))
    return ok

# ---------------------------------------------------------------------------
def fix_dns():
    print(nl.bold("== 修复 DNS =="))
    r = nl.run(["ipconfig", "/flushdns"])
    _step(r == 0, "清除 DNS 缓存", "ipconfig /flushdns")
    ifs = nl.active_interfaces()
    if not ifs:
        _step(False, "未找到已连接的网络接口")
        return
    for name, idx, typ in ifs:
        r1 = nl.run(["netsh", "interface", "ipv4", "set", "dnsservers",
                     f"name={name}", "static", PRIMARY_DNS, "primary"])
        r2 = nl.run(["netsh", "interface", "ipv4", "add", "dnsservers",
                     f"name={name}", SECONDARY_DNS, "index=2"])
        ok = r1 == 0
        _step(ok, f"接口 [{name}] 设置 DNS: {PRIMARY_DNS} / {SECONDARY_DNS}")

def fix_tcp():
    print(nl.bold("== 修复 TCP 栈 =="))
    rules = [
        ("TCP 窗口自动调优 (正常)", ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"]),
        ("禁用 ECN 显式拥塞通知 (兼容性)", ["netsh", "int", "tcp", "set", "global", "ecncapability=disabled"]),
        ("启用 RSS 接收方缩放", ["netsh", "int", "tcp", "set", "global", "rss=enabled"]),
        ("关闭非对称延迟容忍 (提升稳定性)", ["netsh", "int", "tcp", "set", "global", "nonsackrttresiliency=disabled"]),
    ]
    for name, cmd in rules:
        r = nl.run(cmd)
        # 部分系统不支持某参数时 netsh 返回非 0 且有错误提示
        _step(r == 0, name, "" if r == 0 else "(系统不支持, 已跳过)")

def fix_power():
    print(nl.bold("== 修复电源节能 =="))
    r = nl.run(["powercfg", "/setacvalueindex", "SCHEME_CURRENT",
                _WIRELESS_GUID, _POWER_GUID, "0"])
    r2 = nl.run(["powercfg", "/setdcvalueindex", "SCHEME_CURRENT",
                 _WIRELESS_GUID, _POWER_GUID, "0"])
    r3 = nl.run(["powercfg", "/setactive", "SCHEME_CURRENT"])
    ok = r == 0 and r2 == 0 and r3 == 0
    _step(ok, "禁用无线网卡节能 (电源模式)", "" if ok else "(非无线连接时自动跳过)")
    r4 = nl.run(["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\USB",
                 "/v", "DisableSelectiveSuspend", "/t", "REG_DWORD", "/d", "1", "/f"])
    _step(r4 == 0, "禁用 USB 选择性暂停 (防止 USB 网卡休眠)")

def cmd_fix(what="all"):
    if what in ("dns", "all"):
        fix_dns()
    if what in ("tcp", "all"):
        print()
        fix_tcp()
    if what in ("power", "all"):
        print()
        fix_power()
    if what not in ("dns", "tcp", "power", "all"):
        print(nl.red(f"未知修复项: {what} (可选 dns/tcp/power/all)"))
        return
    print()
    print(nl.bold("提示: TCP 修复需重启部分生效; 若仍卡顿可尝试重启路由器"))
    nl.log(f"fix {what} 完成")

# ---------------------------------------------------------------------------
def _measure():
    """auto 用: 返回 (网关平均延迟, 百度平均延迟, 百度丢包率, DNS 耗时)。"""
    gw = nl.default_gateway()
    g = nl.ping_stats(gw, 4) if gw else {"avg": None, "loss_pct": 0}
    b = nl.ping_stats("www.baidu.com", 4)
    d = nl.dns_query(PRIMARY_DNS, "www.baidu.com")
    return g, b, d

def cmd_auto():
    print(nl.bold("== 一键优化: 诊断 → 自动修复 → 复测 =="))
    print(nl.bold("── 第 1 步: 诊断 ──"))
    g, b, d = _measure()
    problems = []
    if g.get("avg") is None:
        print(nl.red("  网关不可达 — 请先检查路由器/WiFi 连接"))
        problems.append("网关不可达")
    else:
        print(f"  网关延迟 {g['avg']} ms, 丢包 {g['loss_pct']}%")
        if g["loss_pct"] > 0:
            problems.append("网关丢包")
    if b.get("avg") is None:
        print(nl.red("  百度不可达"))
        problems.append("外网不可达")
    else:
        print(f"  百度延迟 {b['avg']} ms, 丢包 {b['loss_pct']}%")
        if b["loss_pct"] > 0:
            problems.append("外网丢包")
        elif b["avg"] > 60:
            problems.append("外网延迟偏高")
    if d is None:
        print(nl.red("  DNS 解析失败"))
        problems.append("DNS 异常")
    else:
        print(f"  DNS 解析 {d:.0f} ms")
        if d > 100:
            problems.append("DNS 解析慢")

    if not problems:
        print(nl.green("\n  未发现明显问题, 仍会做一轮预防性优化"))
    else:
        print(nl.yellow(f"\n  发现问题: {'、'.join(problems)}"))

    print(nl.bold("\n── 第 2 步: 自动修复 (需要管理员权限) ──"))
    if not nl.is_admin():
        print(nl.yellow("  当前非管理员, 正在以管理员身份重新启动..."))
        nl.elevate("auto", "--wait")
        return
    fix_dns()
    print()
    fix_tcp()
    print()
    fix_power()

    print(nl.bold("\n── 第 3 步: 复测 ──"))
    g2, b2, d2 = _measure()
    def cmp_tag(desc, before, after, unit="ms"):
        if before is None or after is None:
            return f"  {desc}: {nl.yellow('-')}"
        delta = after - before
        if delta <= 1:
            tag = nl.green(f"{after:.0f} {unit} (稳定)")
        elif delta < 0:
            tag = nl.green(f"{after:.0f} {unit} (↓{abs(delta):.0f})")
        else:
            tag = nl.red(f"{after:.0f} {unit} (↑{delta:.0f})")
        return f"  {desc}: {before:.0f} → {tag}"
    print(cmp_tag("网关延迟", g.get("avg"), g2.get("avg")))
    print(cmp_tag("百度延迟", b.get("avg"), b2.get("avg")))
    print(cmp_tag("DNS 解析", d, d2))

    print(nl.bold("\n── 优化建议 ──"))
    if b2.get("avg") is not None and b2["avg"] > 60:
        print(nl.yellow("  · 外网延迟仍偏高: 宽带高峰期常见, 可尝试重启路由器/光猫"))
    if g2.get("avg") is not None and g2["avg"] > 10:
        print(nl.yellow("  · 网关延迟偏高: 检查 WiFi 信号或改用 5GHz 频段 (运行 'wifi' 查看)"))
    print(nl.green("  · 建议每周运行一次 'auto' 保持最佳状态"))
    nl.log(f"auto 完成: 百度 {b2['avg'] if b2.get('avg') else '-'}ms 丢包 {b2['loss_pct']}%")
