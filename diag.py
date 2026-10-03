# -*- coding: utf-8 -*-
"""诊断命令：ping / dns / http / trace / wifi / monitor / speed / status / full。"""
import re
import time
import urllib.request

import netlib as nl

DNS_SERVERS = [
    ("阿里 AliDNS",  "223.5.5.5"),
    ("腾讯 DNSPod",  "119.29.29.29"),
    ("114 DNS",      "114.114.114.114"),
    ("谷歌 Google",   "8.8.8.8"),
    ("Cloudflare",   "1.1.1.1"),
    ("百度 Baidu",    "180.76.76.76"),
    ("OpenDNS",      "208.67.222.222"),
]

HTTP_SITES = [
    ("百度",   "www.baidu.com"),
    ("腾讯",   "www.qq.com"),
    ("B 站",   "www.bilibili.com"),
    ("微软",   "www.microsoft.com"),
]

SPEED_DOWNLOADS = [
    ("Cloudflare", "https://speed.cloudflare.com/__down?bytes=20000000"),
    ("阿里云镜像",  "https://mirrors.aliyun.com/centos/7/isos/x86_64/CentOS-7-x86_64-Minimal-2009.iso"),
    ("清华镜像",   "https://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.2-desktop-amd64.iso"),
]

def _ms(v):
    return f"{v:.1f}" if v is not None else "-"

def _stat_line(label, stat, good, warn):
    if stat.get("avg") is None:
        return f"  {label:<8} {nl.red('不可达')}"
    s = f"  {label:<8} 平均 {stat['avg']:>7} ms   丢包 {stat['loss_pct']:>4}%"
    if stat["loss_pct"] > 0:
        return s + "  " + nl.red("有丢包!")
    if stat["avg"] <= good:
        return s + "  " + nl.green("正常")
    if stat["avg"] <= warn:
        return s + "  " + nl.yellow("偏慢")
    return s + "  " + nl.red("很慢")

# ---------------------------------------------------------------------------
def cmd_ping(target=None):
    if not target:
        target = "www.baidu.com"
    gw = nl.default_gateway()
    print(nl.bold(f"== 延迟测试: {target} =="))
    if gw:
        g = nl.ping_stats(gw, 4)
        print(_stat_line("网关 " + gw, g, 5, 30))
    s = nl.ping_stats(target, 4)
    print(_stat_line(target, s, 30, 100))
    if s["avg"] is not None:
        print(f"\n  最低 {s['min']} ms   最高 {s['max']} ms   抖动 {s['jitter']} ms")
    if gw:
        nl.log(f"ping {target}: 网关 {_ms(g['avg'])}ms/丢包{g['loss_pct']}% "
               f"| 目标 {_ms(s['avg'])}ms/丢包{s['loss_pct']}%")

# ---------------------------------------------------------------------------
def cmd_dns():
    print(nl.bold("== DNS 解析基准 (查询 www.baidu.com, 取 3 次平均) =="))
    cur = nl.current_dns()
    if cur:
        print("  当前系统 DNS: " + ", ".join(cur))
    results = []
    for name, server in DNS_SERVERS:
        times = [t for t in (nl.dns_query(server, "www.baidu.com") for _ in range(3)) if t is not None]
        avg = sum(times) / len(times) if times else None
        results.append((name, server, avg))
    results.sort(key=lambda r: (r[2] is None, r[2] if r[2] is not None else 1e9))
    print("  排行   服务器          地址            平均耗时")
    for i, (name, server, avg) in enumerate(results, 1):
        if avg is None:
            line = f"  {i:<5} {name:<12} {server:<13} {nl.red('超时/不可达')}"
        elif avg <= 30:
            line = f"  {i:<5} {name:<12} {server:<13} {nl.green(f'{avg:6.1f} ms')}"
        elif avg <= 100:
            line = f"  {i:<5} {name:<12} {server:<13} {nl.yellow(f'{avg:6.1f} ms')}"
        else:
            line = f"  {i:<5} {name:<12} {server:<13} {nl.red(f'{avg:6.1f} ms')}"
        print(line)
    nl.log("dns 基准: " + "; ".join(f"{n}={_ms(a)}" for n, _, a in results))

# ---------------------------------------------------------------------------
def cmd_http():
    print(nl.bold("== HTTP 延迟测试 (HTTPS 首字节 TTFB) =="))
    log_parts = []
    for name, host in HTTP_SITES:
        t = nl.http_ttfb(host)
        log_parts.append(f"{host}={'失败' if t is None else f'{t:.0f}ms'}")
        if t is None:
            print(f"  {name:<6} {host:<22} {nl.red('连接失败')}")
        elif t <= 150:
            print(f"  {name:<6} {host:<22} {nl.green(f'{t:6.1f} ms')}")
        elif t <= 500:
            print(f"  {name:<6} {host:<22} {nl.yellow(f'{t:6.1f} ms')}")
        else:
            print(f"  {name:<6} {host:<22} {nl.red(f'{t:6.1f} ms')}")
    nl.log("http: " + "; ".join(log_parts))

# ---------------------------------------------------------------------------
def cmd_trace(target=None):
    if not target:
        target = "www.baidu.com"
    print(nl.bold(f"== 路由追踪: {target} (最多 20 跳) =="))
    nl.run(["tracert", "-d", "-h", "20", "-w", "800", target], timeout=120, show=True)

# ---------------------------------------------------------------------------
def _parse_wlan_interface(out):
    info = {}
    for line in out.splitlines():
        m = re.match(r"^\s*(SSID|信号|信道|频段|接收速率|传输速率)\s*:\s*(.+)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key == "SSID" and "BSSID" in line:
                continue
            info[key] = val
        m2 = re.match(r"^\s*(SSID|Signal|Channel|Band|Receive rate|Transmit rate)\s*:\s*(.+)$", line)
        if m2:
            key, val = m2.group(1), m2.group(2).strip()
            if key == "SSID" and "BSSID" in line:
                continue
            info.setdefault(key, val)
    return info

def cmd_wifi():
    code, out = nl.run(["netsh", "wlan", "show", "interfaces"])
    print(nl.bold("== WiFi 状态 =="))
    if "已连接" not in out and "connected" not in out.lower():
        print(nl.red("  未连接到任何 WiFi"))
        return
    info = _parse_wlan_interface(out)
    keys = [("SSID", "SSID"), ("信号", "Signal"), ("信道", "Channel"),
            ("频段", "Band"), ("接收速率", "Receive rate"), ("传输速率", "Transmit rate")]
    shown = False
    for zh, en in keys:
        v = info.get(zh) or info.get(en)
        if v:
            print(f"  {zh}: {v}")
            shown = True
    if not shown:
        print("  " + out.strip()[:500])
    sig = (info.get("信号") or info.get("Signal") or "").strip("%")
    try:
        s = int(sig)
        if s >= 70:
            print(nl.green(f"  信号强度: {s}% 良好"))
        elif s >= 40:
            print(nl.yellow(f"  信号强度: {s}% 一般"))
        else:
            print(nl.red(f"  信号强度: {s}% 差"))
    except ValueError:
        pass

    print(nl.bold("\n== 周边网络与信道占用 =="))
    code, out2 = nl.run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    channels = {}
    cur_channel = None
    for line in out2.splitlines():
        m = re.search(r"(?:信道|Channel)\s*:\s*(\d+)", line)
        if m:
            ch = int(m.group(1))
            channels[ch] = channels.get(ch, 0) + 1
    # 当前信道
    m = re.search(r"(?:信道|Channel)\s*:\s*(\d+)", out)
    if m:
        cur_channel = int(m.group(1))
    if channels:
        occ = sorted(channels.items(), key=lambda x: x[1], reverse=True)
        bar = "  " + "  ".join(f"信道{c}:{n}" for c, n in occ[:8])
        print(bar)
        if cur_channel and cur_channel in channels:
            rank = [c for c, n in occ].index(cur_channel) + 1
            print(f"  当前信道 {cur_channel} 拥堵排名第 {rank}")
        free = [c for c, n in occ if n <= 1]
        if free and cur_channel and cur_channel in channels and channels[cur_channel] > 2:
            print(nl.yellow(f"  建议: 路由器可尝试换到空闲信道 {free[0]}"))
    nl.log("wifi 检查完成")

# ---------------------------------------------------------------------------
def cmd_monitor(count=60, stop_event=None):
    print(nl.bold(f"== 百度延迟采样 ({count} 次, 每秒 1 次, Ctrl+C 提前结束) =="))
    times = []
    loss = 0
    try:
        for i in range(count):
            if stop_event and stop_event.is_set():
                print(nl.yellow("\n  已手动停止"))
                break
            t0 = time.perf_counter()
            code, out = nl.run(["ping", "-n", "1", "-w", "1000", "www.baidu.com"], timeout=3)
            m = re.search(r"(?:时间|time)[=\s<>]*([\d.]+)\s*ms", out, re.I)
            if m:
                t = float(m.group(1))
                times.append(t)
                mark = nl.green(f"{t:6.1f} ms") if t < 100 else (nl.yellow(f"{t:6.1f} ms") if t < 300 else nl.red(f"{t:6.1f} ms"))
            else:
                loss += 1
                mark = nl.red("  超时")
            elapsed = time.perf_counter() - t0
            print(f"\r  第 {i + 1:>3}/{count} 次  {mark}      ", end="", flush=True)
            if elapsed < 1:
                time.sleep(1 - elapsed)
    except KeyboardInterrupt:
        print()
    print()
    if not times:
        print(nl.red("  全部超时，网络不可用"))
        return
    avg = sum(times) / len(times)
    jitter = sum(abs(t - avg) for t in times) / len(times)
    print(f"\n  采样 {len(times)} 次  最低 {min(times):.1f} ms  最高 {max(times):.1f} ms"
          f"  平均 {avg:.1f} ms  抖动 {jitter:.1f} ms  丢包 {loss} 次")
    bursts = 0
    cur = 0
    for t in times:
        if t > 200:
            cur += 1
            bursts = max(bursts, cur)
        else:
            cur = 0
    print(f"  最大连续高延迟(>200ms): {bursts} 次")
    if bursts >= 3:
        print(nl.yellow("  提示: 出现持续高延迟，建议运行 'auto' 或检查路由器"))
    nl.log(f"monitor: {len(times)} 次采样, 平均 {avg:.1f}ms, 丢包 {loss}, 最高 {max(times):.1f}ms")

# ---------------------------------------------------------------------------
def _download_mbps(url, max_seconds=15):
    """下载测速，返回 Mbps 或 None。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "net-optimizer/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            t0 = time.perf_counter()
            total = 0
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if time.perf_counter() - t0 > max_seconds:
                    break
            dt = time.perf_counter() - t0
            if dt <= 0 or total <= 0:
                return None
            return total * 8 / dt / 1e6
    except Exception:
        return None

def _upload_mbps(url="https://speed.cloudflare.com/__up", max_seconds=15):
    """上传测速，返回 Mbps 或 None。"""
    try:
        data = b"x" * (4 * 1024 * 1024)  # 4MB
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"User-Agent": "net-optimizer/1.0"})
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=max_seconds) as r:
            r.read()
        dt = time.perf_counter() - t0
        if dt <= 0:
            return None
        return len(data) * 8 / dt / 1e6
    except Exception:
        return None

def cmd_speed():
    print(nl.bold("== 带宽测速 (下载+上传, 单线程) =="))
    print("  下载中...")
    best = None
    best_src = ""
    for name, url in SPEED_DOWNLOADS:
        mbps = _download_mbps(url)
        if mbps is not None and (best is None or mbps > best):
            best, best_src = mbps, name
    if best is None:
        print(nl.red("  下载测速失败: 所有测速源不可达"))
    else:
        tag = nl.green(f"{best:6.2f} Mbps") if best > 50 else (nl.yellow(f"{best:6.2f} Mbps") if best > 10 else nl.red(f"{best:6.2f} Mbps"))
        print(f"  下载: {tag}   (测速源: {best_src})")
    print("  上传中 (约 4MB)...")
    up = _upload_mbps()
    if up is None:
        print(nl.yellow("  上传测速失败 (测速点不可达), 已跳过"))
    else:
        tag = nl.green(f"{up:6.2f} Mbps") if up > 20 else (nl.yellow(f"{up:6.2f} Mbps") if up > 5 else nl.red(f"{up:6.2f} Mbps"))
        print(f"  上传: {tag}")
    nl.log(f"speed: 下载 {best:.2f}Mbps({best_src}) 上传 {up:.2f}Mbps" if best else "speed: 测速失败")

# ---------------------------------------------------------------------------
def _mtu_line(mtu):
    if mtu is None:
        return "  MTU 探测失败"
    if mtu >= 1472:
        return f"  MTU: {mtu}  " + nl.green("标准 1500, 正常")
    if mtu >= 1400:
        return f"  MTU: {mtu}  " + nl.yellow("略低")
    return f"  MTU: {mtu}  " + nl.red("偏低, 可能影响大包传输")

def cmd_status():
    print(nl.bold("== 快速诊断 =="))
    gw = nl.default_gateway()
    if gw:
        g = nl.ping_stats(gw, 4)
        print(_stat_line("网关 " + gw, g, 5, 30))
        if g["avg"] is None:
            print(nl.red("  !! 网关不可达: 检查网线/WiFi 连接与路由器"))
    else:
        print(nl.yellow("  未找到默认网关 (可能未联网)"))
    b = nl.ping_stats("www.baidu.com", 4)
    print(_stat_line("百度", b, 30, 100))
    if b["avg"] is None:
        print(nl.red("  !! 外网不可达: 检查拨号/宽带状态或运行 'fix dns'"))
    cur = nl.current_dns()
    if cur:
        dn = [nl.dns_query(d, "www.baidu.com") for d in cur[:2]]
        dn = [t for t in dn if t is not None]
        if dn:
            avg = sum(dn) / len(dn)
            tag = nl.green(f"{avg:.0f} ms 正常") if avg <= 50 else (nl.yellow(f"{avg:.0f} ms 偏慢") if avg <= 150 else nl.red(f"{avg:.0f} ms 很慢"))
            print(f"  DNS 解析  当前 " + ", ".join(cur[:2]) + f"  →  {tag}")
        else:
            print(nl.red("  DNS 解析失败: 建议运行 'fix dns'"))
    t = nl.http_ttfb("www.baidu.com")
    if t is not None:
        tag = nl.green(f"{t:.0f} ms 正常") if t <= 150 else (nl.yellow(f"{t:.0f} ms 偏慢") if t <= 500 else nl.red(f"{t:.0f} ms 很慢"))
        print(f"  HTTP 延迟  百度 HTTPS    {tag}")
    else:
        print(nl.red("  HTTP 连接百度失败"))
    m = nl.mtu_probe()
    print(_mtu_line(m))
    nl.log(f"status: 网关{_ms(g['avg']) if gw else '-'}ms 百度{_ms(b['avg'])}ms 丢包{b['loss_pct']}%")

def cmd_full():
    cmd_status()
    print()
    cmd_speed()
    print()
    cmd_trace()
    print()
    cmd_wifi()
