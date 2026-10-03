# -*- coding: utf-8 -*-
"""诊断命令的编排层 —— 探测 → 渲染 → 打印（BRIEF §5 三层架构）。

1. **探测**：``probes.*`` 或可注入的 ``run`` 拿数据，**不打印**；
2. **渲染**：``render_*`` 纯函数，``(数据...) -> list[str]`` 或 ``-> str``，
   只拼字符串（颜色走 :mod:`netopt.ui`），不调 probes、不做 IO；
3. **编排**：``cmd_*`` 串起前两步并打印。

所有 ``cmd_*`` 都接受可注入的 ``run``（``platform.Runner``），默认值**在调用时**
解析（BRIEF §5：不能写成 def 默认参数，否则测试 monkeypatch 追不到）。
测试用 ``fake_run`` + 真实 fixture 驱动端到端，用构造数据驱动 ``render_*``。

依赖注入注意（命名冲突）：本包内一律显式 ``from netopt import ...``，
项目根还有一个**旧的** ``diag.py``，裸 ``import diag`` 会 import 错模块。
"""

from __future__ import annotations

import time
import urllib.request
from dataclasses import dataclass

from netopt import parsers, platform, probes, state, ui
from netopt.models import ChannelOccupancy, DnsConfig, MtuResult, PingStat, WlanInfo
from netopt.platform import CmdResult, Runner

# ---------------------------------------------------------------------------
# 命令行字面量（与旧 diag.py 保持一致，CLI/GUI 按钮依赖）
# ---------------------------------------------------------------------------

DNS_SERVERS = [
    ("阿里 AliDNS", "223.5.5.5"),
    ("腾讯 DNSPod", "119.29.29.29"),
    ("114 DNS", "114.114.114.114"),
    ("谷歌 Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("百度 Baidu", "180.76.76.76"),
    ("OpenDNS", "208.67.222.222"),
]

HTTP_SITES = [
    ("百度", "www.baidu.com"),
    ("腾讯", "www.qq.com"),
    ("B 站", "www.bilibili.com"),
    ("微软", "www.microsoft.com"),
]

#: 测速源（D10）。三个源于 2026-10-03 在本机用 urllib（与代码相同 UA/路径）
#: **实测**均可用：Cloudflare 200 / 阿里云 200 / 清华 200。
#: 选固定文件名 ``ls-lR.gz``（每个 Ubuntu 镜像站都有、不含版本号），
#: 取代旧实现那些带版本号、随发布周期腐烂的 ISO 路径。
SPEED_DOWNLOADS = [
    ("Cloudflare", "https://speed.cloudflare.com/__down?bytes=20000000"),
    ("阿里云镜像", "https://mirrors.aliyun.com/ubuntu/ls-lR.gz"),
    ("清华镜像", "https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ls-lR.gz"),
]

#: 上传测速点（Cloudflare 的 ``__up`` 端点，旧实现唯一还活着的部分）。
SPEED_UPLOAD = ("Cloudflare", "https://speed.cloudflare.com/__up")

_USER_AGENT = "net-optimizer/1.0"


# ---------------------------------------------------------------------------
# 渲染层：ping / MTU
# ---------------------------------------------------------------------------


def render_stat_line(label: str, stat: PingStat, good: float, warn: float) -> str:
    """一行 ping 统计（网关与目标共用）。

    ``good`` / ``warn`` 是平均延迟分档阈值（毫秒）：≤good 正常、≤warn 偏慢。
    """
    head = "  " + ui.pad(label, 16)
    if stat.avg_ms is None:
        return head + ui.red("不可达")
    line = f"{head} 平均 {stat.avg_ms:>7.1f} ms   丢包 {stat.loss_pct:>5.1f}%"
    if stat.loss_pct > 0:
        return line + "  " + ui.red("有丢包!")
    if stat.avg_ms <= good:
        return line + "  " + ui.green("正常")
    if stat.avg_ms <= warn:
        return line + "  " + ui.yellow("偏慢")
    return line + "  " + ui.red("很慢")


def render_mtu_line(result: MtuResult) -> str:
    """MTU 分档渲染 —— D6 的修复点，阈值单位是 **MTU 本体**（payload + 28）。

    旧实现用 payload 阈值 ``mtu >= 1472`` 去比 MTU 本体，把本机 PPPoE 1492
    标成「标准 1500, 正常」——自相矛盾，且放过了 PPPoE 这个最常见的卡顿成因。
    """
    if not result.found or result.mtu is None:
        return "  MTU 探测失败"
    mtu = result.mtu
    if result.is_standard_ethernet():
        tag = ui.green("标准 1500, 正常")
    elif result.is_pppoe():
        tag = ui.yellow("PPPoE 拨号线路, 大包可能受限")
    elif mtu >= 1400:
        tag = ui.yellow("略低")
    else:
        tag = ui.red("偏低, 可能影响大包传输")
    line = f"  MTU: {mtu}  {tag}"
    if not result.verified:
        line += "  " + ui.yellow("(探测未经确认, 仅供参考)")
    return line


# ---------------------------------------------------------------------------
# 渲染层：DNS / HTTP
# ---------------------------------------------------------------------------


def collect_dns_servers(configs: list[DnsConfig]) -> list[str]:
    """把各接口的 DNS 服务器去重保序展开（当前生效的解析器列表）。"""
    servers: list[str] = []
    for cfg in configs:
        for server in cfg.servers:
            if server not in servers:
                servers.append(server)
    return servers


def render_dns_row(rank: int, name: str, server: str, avg_ms: float | None) -> str:
    """DNS 基准排行的一行（``cmd_dns`` 用）。"""
    if avg_ms is None:
        tag = ui.red("超时/不可达")
    elif avg_ms <= 30:
        tag = ui.green(f"{avg_ms:6.1f} ms")
    elif avg_ms <= 100:
        tag = ui.yellow(f"{avg_ms:6.1f} ms")
    else:
        tag = ui.red(f"{avg_ms:6.1f} ms")
    return f"  {rank:<5} {ui.pad(name, 12)} {ui.pad(server, 13)} {tag}"


def render_dns_status_line(servers: list[str], avg_ms: float | None) -> str:
    """``status`` 里的 DNS 一行：当前服务器 + 实测解析耗时。"""
    if not servers:
        return ui.yellow("  未检测到 DNS 配置 (可运行 'fix dns')")
    shown = ", ".join(servers[:2])
    if avg_ms is None:
        return ui.red(f"  DNS 解析失败: 当前 {shown} 无响应, 建议运行 'fix dns'")
    if avg_ms <= 50:
        tag = ui.green(f"{avg_ms:.0f} ms 正常")
    elif avg_ms <= 150:
        tag = ui.yellow(f"{avg_ms:.0f} ms 偏慢")
    else:
        tag = ui.red(f"{avg_ms:.0f} ms 很慢")
    return f"  DNS 解析  当前 {shown}  →  {tag}"


def render_http_row(name: str, host: str, ttfb_ms: float | None) -> str:
    """HTTP 延迟表格的一行（``cmd_http`` 用）。"""
    if ttfb_ms is None:
        tag = ui.red("连接失败")
    elif ttfb_ms <= 150:
        tag = ui.green(f"{ttfb_ms:6.1f} ms")
    elif ttfb_ms <= 500:
        tag = ui.yellow(f"{ttfb_ms:6.1f} ms")
    else:
        tag = ui.red(f"{ttfb_ms:6.1f} ms")
    return f"  {ui.pad(name, 6)} {ui.pad(host, 22)} {tag}"


def render_http_status_line(label: str, ttfb_ms: float | None) -> str:
    """``status`` 里的 HTTP 一行。"""
    if ttfb_ms is None:
        return ui.red(f"  HTTP 连接 {label} 失败")
    if ttfb_ms <= 150:
        tag = ui.green(f"{ttfb_ms:.0f} ms 正常")
    elif ttfb_ms <= 500:
        tag = ui.yellow(f"{ttfb_ms:.0f} ms 偏慢")
    else:
        tag = ui.red(f"{ttfb_ms:.0f} ms 很慢")
    return f"  HTTP 延迟  {label}    {tag}"


# ---------------------------------------------------------------------------
# 渲染层：测速（D4 / D10）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SpeedSample:
    """单个测速点的结果：成功记 ``mbps``，失败记 ``error`` 原因。"""

    name: str
    mbps: float | None = None
    error: str | None = None


def _speed_tag(mbps: float, good: float, warn: float) -> str:
    text = f"{mbps:6.2f} Mbps"
    if mbps > good:
        return ui.green(text)
    if mbps > warn:
        return ui.yellow(text)
    return ui.red(text)


def render_speed_downloads(samples: list[SpeedSample]) -> list[str]:
    """下载测速结果：选最快源，并逐条说明被跳过的源（D10 容错可见）。"""
    usable = [s for s in samples if s.mbps is not None]
    lines: list[str] = []
    if not usable:
        lines.append(ui.red("  下载测速失败: 所有测速源不可达"))
    else:
        best = max(usable, key=lambda s: s.mbps or 0.0)
        lines.append(f"  下载: {_speed_tag(best.mbps or 0.0, 50, 10)}   (测速源: {best.name})")
    for s in samples:
        if s.mbps is None:
            lines.append(ui.yellow(f"  跳过 {s.name}: {s.error or '不可用'}"))
    return lines


def render_speed_upload(sample: SpeedSample) -> list[str]:
    """上传测速结果；``mbps is None`` 时只提示跳过（D4：不得崩溃）。"""
    if sample.mbps is None:
        detail = f": {sample.error}" if sample.error else ""
        return [ui.yellow(f"  上传测速失败 (测速点不可达), 已跳过{detail}")]
    return [f"  上传: {_speed_tag(sample.mbps, 20, 5)}"]


def render_speed_log(down: SpeedSample | None, up: SpeedSample | None) -> str:
    """测速结果日志行 —— D4：任一路径失败（``None`` / ``mbps=None``）都不得抛。"""
    if down is not None and down.mbps is not None:
        down_txt = f"{down.mbps:.2f}Mbps({down.name})"
    else:
        down_txt = "失败"
    up_txt = f"{up.mbps:.2f}Mbps" if up is not None and up.mbps is not None else "失败"
    return f"speed: 下载 {down_txt} 上传 {up_txt}"


# ---------------------------------------------------------------------------
# 渲染层：WiFi（D16）
# ---------------------------------------------------------------------------

_LOCATION_MARKERS = ("位置权限", "位置服务", "privacy-location", "location")


def _failure_reason(res: CmdResult) -> str:
    if res.missing:
        return "系统没有该命令"
    if res.timed_out:
        return "命令执行超时"
    return f"命令失败 (rc={res.code})"


def _first_meaningful_line(text: str, limit: int = 120) -> str:
    for raw in text.splitlines():
        line = raw.strip()
        if line:
            return line[:limit]
    return ""


def _mentions_location(text: str) -> bool:
    low = text.lower()
    return any(marker in low for marker in _LOCATION_MARKERS)


def render_wlan_status(info: WlanInfo, res: CmdResult) -> list[str]:
    """``netsh wlan show interfaces`` 的结果渲染。

    ``res`` 不 ok 时明确说明失败原因，而不是把「命令失败」和「没连 WiFi」
    混为一谈。
    """
    if not res.ok:
        lines = [ui.red(f"  无法读取 WiFi 状态: {_failure_reason(res)}")]
        detail = _first_meaningful_line(res.out)
        if detail:
            lines.append(f"  命令输出: {detail}")
        return lines
    if info.connected:
        lines: list[str] = []
        if info.ssid:
            lines.append(f"  SSID: {info.ssid}")
        if info.band:
            lines.append(f"  频段: {info.band}")
        if info.channel is not None:
            lines.append(f"  信道: {info.channel}")
        if info.signal_pct is not None:
            if info.signal_pct >= 70:
                tag = ui.green(f"{info.signal_pct}% 良好")
            elif info.signal_pct >= 40:
                tag = ui.yellow(f"{info.signal_pct}% 一般")
            else:
                tag = ui.red(f"{info.signal_pct}% 差")
            lines.append(f"  信号强度: {tag}")
        if info.rx_mbps is not None:
            lines.append(f"  接收速率: {info.rx_mbps:g} Mbps")
        if info.tx_mbps is not None:
            lines.append(f"  传输速率: {info.tx_mbps:g} Mbps")
        if not lines:
            lines.append(f"  已连接 ({info.state or '状态未知'})")
        return lines
    lines = [ui.red("  未连接到任何 WiFi")]
    if info.state:
        lines.append(f"  状态: {info.state}")
    if info.interface:
        lines.append(f"  接口: {info.interface}")
    return lines


def render_channel_occupancy(occ: ChannelOccupancy) -> list[str]:
    """信道占用：按频段分开统计（2.4G 与 5G 同号信道互不干扰）。"""
    if occ.empty:
        return [ui.yellow("  未扫描到周边 WiFi 网络")]
    lines: list[str] = []
    for band in sorted(occ.by_band):
        counts = occ.by_band[band]
        if not counts:
            continue
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        detail = "  ".join(f"信道{ch}:{n}" for ch, n in top)
        lines.append(f"  {ui.pad(band, 7)} 占用最多: {detail}")
    current = occ.current_channel
    if current is not None:
        ranked = occ.busiest(occ.current_band)
        rank = next((i for i, (ch, _n) in enumerate(ranked, 1) if ch == current), None)
        if rank is not None:
            label = f"  当前信道 {current}"
            if occ.current_band:
                label += f" ({occ.current_band})"
            lines.append(f"{label} 拥堵排名第 {rank}")
            counts = dict(ranked)
            if counts.get(current, 0) > 2:
                free = [ch for ch, n in sorted(ranked, key=lambda kv: (kv[1], kv[0])) if n <= 1]
                if free:
                    lines.append(ui.yellow(f"  建议: 路由器可尝试换到空闲信道 {free[0]}"))
    return lines


def render_wlan_scan(res: CmdResult, occ: ChannelOccupancy) -> list[str]:
    """周边网络扫描结果 —— D16 的修复点。

    旧实现丢弃 ``netsh wlan show networks mode=bssid`` 的返回码，而本机该命令
    rc=1（缺「位置」权限），于是「周边网络与信道占用」板块永远静默空白。
    这里必须把失败原因和开启方式讲清楚。
    """
    if not res.ok:
        lines = [ui.red(f"  无法获取周边网络列表: {_failure_reason(res)}")]
        if _mentions_location(res.out):
            lines.append("  原因: Windows 需要「位置」权限才能列出周边 WiFi 网络")
            lines.append("  开启: 设置 → 隐私和安全性 → 位置 → 打开位置服务")
            lines.append("  或运行: start ms-settings:privacy-location")
        elif "提升" in res.out or "管理员" in res.out:
            lines.append("  提示: 该命令需要管理员权限, 请以管理员身份运行")
        else:
            detail = _first_meaningful_line(res.out)
            if detail:
                lines.append(f"  命令输出: {detail}")
        return lines
    return render_channel_occupancy(occ)


# ---------------------------------------------------------------------------
# 渲染层：monitor / 日志行
# ---------------------------------------------------------------------------


def render_monitor_tick(index: int, total: int, rtt_ms: float | None) -> str:
    """延迟采样的单次进度行（``\\r`` 复用同一行，Ctrl+C 前不刷屏）。"""
    if rtt_ms is None:
        mark = ui.red("  超时")
    elif rtt_ms < 100:
        mark = ui.green(f"{rtt_ms:6.1f} ms")
    elif rtt_ms < 300:
        mark = ui.yellow(f"{rtt_ms:6.1f} ms")
    else:
        mark = ui.red(f"{rtt_ms:6.1f} ms")
    return f"\r  第 {index:>3}/{total} 次  {mark}      "


def render_monitor_summary(samples: list[float], loss: int) -> list[str]:
    """采样结束后的统计（平均/抖动/最大连续高延迟）。"""
    if not samples:
        return [ui.red("  全部超时，网络不可用")]
    avg = sum(samples) / len(samples)
    jitter = sum(abs(t - avg) for t in samples) / len(samples)
    lines = [
        f"\n  采样 {len(samples)} 次  最低 {min(samples):.1f} ms  最高 {max(samples):.1f} ms"
        f"  平均 {avg:.1f} ms  抖动 {jitter:.1f} ms  丢包 {loss} 次"
    ]
    bursts = 0
    run_len = 0
    for t in samples:
        if t > 200:
            run_len += 1
            bursts = max(bursts, run_len)
        else:
            run_len = 0
    lines.append(f"  最大连续高延迟(>200ms): {bursts} 次")
    if bursts >= 3:
        lines.append(ui.yellow("  提示: 出现持续高延迟，建议运行 'auto' 或检查路由器"))
    return lines


def render_status_log(gateway_stat: PingStat | None, target_stat: PingStat) -> str:
    gw_txt = ui.ms(gateway_stat.avg_ms) if gateway_stat is not None else "-"
    return (
        f"status: 网关{gw_txt}ms 百度{ui.ms(target_stat.avg_ms)}ms 丢包{target_stat.loss_pct:.1f}%"
    )


def render_ping_log(target: str, gateway_stat: PingStat | None, stat: PingStat) -> str:
    if gateway_stat is not None:
        gw_part = f"网关 {ui.ms(gateway_stat.avg_ms)}ms/丢包{gateway_stat.loss_pct:.1f}%"
    else:
        gw_part = "网关 -"
    return f"ping {target}: {gw_part} | 目标 {ui.ms(stat.avg_ms)}ms/丢包{stat.loss_pct:.1f}%"


def render_monitor_log(samples: list[float], loss: int) -> str:
    if not samples:
        return "monitor: 全部超时"
    avg = sum(samples) / len(samples)
    return (
        f"monitor: {len(samples)} 次采样, 平均 {avg:.1f}ms, 丢包 {loss}, 最高 {max(samples):.1f}ms"
    )


# ---------------------------------------------------------------------------
# 探测层：不打印，只产出数据
# ---------------------------------------------------------------------------


def _resolve(run: Runner | None) -> Runner:
    """调用时解析默认 runner（BRIEF §5：不能绑定成 def 默认参数）。"""
    return run if run is not None else platform.run


def _download_sample(name: str, url: str, max_seconds: float = 15.0) -> SpeedSample:
    """下载测速：成功返回 Mbps，失败返回**原因**（D10：单源失败不拖垮整体）。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            started = time.perf_counter()
            total = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if time.perf_counter() - started > max_seconds:
                    break
            elapsed = time.perf_counter() - started
        if elapsed <= 0 or total <= 0:
            return SpeedSample(name, None, "没有收到数据")
        return SpeedSample(name, total * 8 / elapsed / 1e6)
    except Exception as exc:
        return SpeedSample(name, None, f"{type(exc).__name__}: {exc}"[:120])


def _upload_sample(name: str, url: str, max_seconds: float = 15.0) -> SpeedSample:
    """上传测速：4MB POST，成功返回 Mbps，失败返回原因。"""
    try:
        data = b"x" * (4 * 1024 * 1024)
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={"User-Agent": _USER_AGENT},
        )
        started = time.perf_counter()
        with urllib.request.urlopen(req, timeout=max_seconds) as resp:
            resp.read()
        elapsed = time.perf_counter() - started
        if elapsed <= 0:
            return SpeedSample(name, None, "耗时异常")
        return SpeedSample(name, len(data) * 8 / elapsed / 1e6)
    except Exception as exc:
        return SpeedSample(name, None, f"{type(exc).__name__}: {exc}"[:120])


def _band_for_channel(channel: int) -> str | None:
    if 1 <= channel <= 14:
        return "2.4GHz"
    if channel >= 32:
        return "5GHz"
    return None


def _dev_echo(text: str) -> None:
    """开发者模式回显原始输出（旧 netlib.run(show=) 的职责归编排层）。"""
    if state.DEV_ON and text.strip():
        print(text.rstrip())


# ---------------------------------------------------------------------------
# 编排层：cmd_*
# ---------------------------------------------------------------------------


def cmd_status(run: Runner | None = None) -> None:
    """快速诊断：网关 / 外网 / DNS / HTTP / MTU。"""
    run = _resolve(run)
    print(ui.bold("== 快速诊断 =="))

    gateway = probes.gateway(run)
    gateway_stat: PingStat | None = None
    if gateway is not None:
        gateway_stat = probes.ping(gateway.ip, 4, run=run)
        _dev_echo(gateway_stat.raw)
        print(render_stat_line(f"网关 {gateway.ip}", gateway_stat, 5, 30))
        if not gateway_stat.reachable:
            print(ui.red("  !! 网关不可达: 检查网线/WiFi 连接与路由器"))
    else:
        print(ui.yellow("  未找到默认网关 (可能未联网)"))

    target_stat = probes.ping("www.baidu.com", 4, run=run)
    _dev_echo(target_stat.raw)
    print(render_stat_line("百度", target_stat, 30, 100))
    if not target_stat.reachable:
        print(ui.red("  !! 外网不可达: 检查拨号/宽带状态或运行 'fix dns'"))

    servers = collect_dns_servers(probes.dns_config(run))
    times = [
        t for t in (probes.dns_query(s, "www.baidu.com") for s in servers[:2]) if t is not None
    ]
    dns_avg = sum(times) / len(times) if times else None
    print(render_dns_status_line(servers, dns_avg if servers else None))

    print(render_http_status_line("百度 HTTPS", probes.http_ttfb("www.baidu.com")))
    print(render_mtu_line(probes.mtu(run=run)))
    state.log(render_status_log(gateway_stat, target_stat))


def cmd_full(run: Runner | None = None) -> None:
    """全面诊断：status → speed → trace → wifi。"""
    run = _resolve(run)
    cmd_status(run)
    print()
    cmd_speed(run)
    print()
    cmd_trace(None, run)
    print()
    cmd_wifi(run)


def cmd_ping(target: str | None = None, run: Runner | None = None) -> None:
    """延迟测试：默认目标百度，附带网关对比。"""
    target = target or "www.baidu.com"
    run = _resolve(run)
    gateway = probes.gateway(run)
    print(ui.bold(f"== 延迟测试: {target} =="))

    gateway_stat: PingStat | None = None
    if gateway is not None:
        gateway_stat = probes.ping(gateway.ip, 4, run=run)
        _dev_echo(gateway_stat.raw)
        print(render_stat_line(f"网关 {gateway.ip}", gateway_stat, 5, 30))

    stat = probes.ping(target, 4, run=run)
    _dev_echo(stat.raw)
    print(render_stat_line(target, stat, 30, 100))
    if stat.avg_ms is not None:
        print(
            f"\n  最低 {ui.ms(stat.min_ms)} ms   最高 {ui.ms(stat.max_ms)} ms"
            f"   抖动 {ui.ms(stat.jitter_ms)} ms"
        )
    if gateway is not None:
        state.log(render_ping_log(target, gateway_stat, stat))


def cmd_dns(run: Runner | None = None) -> None:
    """DNS 解析基准：7 个公共 DNS 各查 3 次取平均，附当前系统 DNS。"""
    run = _resolve(run)
    print(ui.bold("== DNS 解析基准 (查询 www.baidu.com, 取 3 次平均) =="))
    servers = collect_dns_servers(probes.dns_config(run))
    if servers:
        print("  当前系统 DNS: " + ", ".join(servers))

    results: list[tuple[str, str, float | None]] = []
    for name, server in DNS_SERVERS:
        times = [
            t
            for t in (probes.dns_query(server, "www.baidu.com") for _ in range(3))
            if t is not None
        ]
        avg = sum(times) / len(times) if times else None
        results.append((name, server, avg))
    results.sort(key=lambda r: (r[2] is None, r[2] if r[2] is not None else 1e9))

    print("  排行   服务器          地址            平均耗时")
    for i, (name, server, avg) in enumerate(results, 1):
        print(render_dns_row(i, name, server, avg))
    state.log("dns 基准: " + "; ".join(f"{name}={ui.ms(avg)}" for name, _s, avg in results))


def cmd_http(run: Runner | None = None) -> None:
    """HTTP 延迟测试（HTTPS 首字节 TTFB）。

    ``run`` 只为统一所有 ``cmd_*`` 的注入签名而保留：本命令全部走
    :func:`probes.http_ttfb`（socket），不需要系统命令。
    """
    print(ui.bold("== HTTP 延迟测试 (HTTPS 首字节 TTFB) =="))
    parts: list[str] = []
    for name, host in HTTP_SITES:
        ttfb = probes.http_ttfb(host)
        parts.append(f"{host}={'失败' if ttfb is None else f'{ttfb:.0f}ms'}")
        print(render_http_row(name, host, ttfb))
    state.log("http: " + "; ".join(parts))


def cmd_speed(run: Runner | None = None) -> None:
    """带宽测速（下载+上传，单线程）。

    ``run`` 只为统一注入签名而保留：测速走 HTTP 下载/上传，不经系统命令。
    下载逐个测速源尝试，任一源不可用只跳过并说明原因（D10）；上传失败不崩溃（D4）。
    """
    print(ui.bold("== 带宽测速 (下载+上传, 单线程) =="))
    print("  下载中...")
    samples = [_download_sample(name, url) for name, url in SPEED_DOWNLOADS]
    print("\n".join(render_speed_downloads(samples)))

    print("  上传中 (约 4MB)...")
    upload = _upload_sample(*SPEED_UPLOAD)
    print("\n".join(render_speed_upload(upload)))

    best = max(
        (s for s in samples if s.mbps is not None), key=lambda s: s.mbps or 0.0, default=None
    )
    state.log(render_speed_log(best, upload))


def cmd_trace(target: str | None = None, run: Runner | None = None) -> None:
    """路由追踪（tracert，最多 20 跳），原始输出直接回显。"""
    target = target or "www.baidu.com"
    run = _resolve(run)
    print(ui.bold(f"== 路由追踪: {target} (最多 20 跳) =="))
    res = run(["tracert", "-d", "-h", "20", "-w", "800", target], timeout=120.0)
    if res.out.strip():
        print(res.out.rstrip())
    if not res.ok:
        print(ui.yellow(f"  tracert 未正常完成: {_failure_reason(res)}"))


def cmd_wifi(run: Runner | None = None) -> None:
    """WiFi 状态 + 周边网络信道占用。

    D16：``show networks`` 的返回码必须检查；失败时把原因与开启方式告诉用户，
    不再静默空白。且**不再在未连接时提前返回**——信道扫描与是否已连接无关。
    """
    run = _resolve(run)
    print(ui.bold("== WiFi 状态 =="))
    res = run(["netsh", "wlan", "show", "interfaces"])
    _dev_echo(res.out)
    info = parsers.parse_wlan_interfaces(res.out) if res.ok else WlanInfo()
    print("\n".join(render_wlan_status(info, res)))

    print(ui.bold("\n== 周边网络与信道占用 =="))
    scan = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    _dev_echo(scan.out)
    occupancy = parsers.parse_wlan_networks(scan.out) if scan.ok else ChannelOccupancy()
    if scan.ok and info.channel is not None:
        occupancy = ChannelOccupancy(
            by_band=occupancy.by_band,
            current_channel=info.channel,
            current_band=_band_for_channel(info.channel),
        )
    print("\n".join(render_wlan_scan(scan, occupancy)))
    state.log("wifi 检查完成")


def cmd_monitor(
    count: int = 60,
    stop_event: object | None = None,
    run: Runner | None = None,
) -> None:
    """百度延迟采样（每秒 1 次，可被 ``stop_event`` 提前叫停）。"""
    run = _resolve(run)
    print(ui.bold(f"== 百度延迟采样 ({count} 次, 每秒 1 次, Ctrl+C 提前结束) =="))
    samples: list[float] = []
    loss = 0
    try:
        for i in range(count):
            if stop_event is not None and stop_event.is_set():  # type: ignore[attr-defined]
                print(ui.yellow("\n  已手动停止"))
                break
            started = time.perf_counter()
            stat = probes.ping("www.baidu.com", count=1, timeout_ms=1000, run=run)
            _dev_echo(stat.raw)
            rtt = stat.avg_ms
            if rtt is None:
                loss += 1
            else:
                samples.append(rtt)
            print(render_monitor_tick(i + 1, count, rtt), end="", flush=True)
            elapsed = time.perf_counter() - started
            if elapsed < 1:
                time.sleep(1 - elapsed)
    except KeyboardInterrupt:
        print()
    print()

    print("\n".join(render_monitor_summary(samples, loss)))
    state.log(render_monitor_log(samples, loss))
