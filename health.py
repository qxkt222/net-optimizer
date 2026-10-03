# -*- coding: utf-8 -*-
"""健康评分: 综合诊断 → 0-100 分 → 优化建议, 并记录历史趋势。"""
import re
import time

import netlib as nl

def _score_linear(value, perfect, poor, score_perfect):
    """value<=perfect 得满分; value>=poor 得 0; 中间线性。value 为 None 得 0。"""
    if value is None:
        return 0
    if value <= perfect:
        return score_perfect
    if value >= poor:
        return 0
    ratio = (poor - value) / (poor - perfect)
    return round(score_perfect * ratio)

def cmd_health():
    print(nl.bold("== 健康评分 =="))
    scores = []
    details = []
    advice = []

    gw = nl.default_gateway()
    g = nl.ping_stats(gw, 4) if gw else {"avg": None, "loss_pct": 100}
    s = _score_linear(g["avg"], 5, 50, 15) + (0 if g["loss_pct"] <= 2 else (0 if g["loss_pct"] == 100 else 5))
    if g["loss_pct"] > 2 and g["loss_pct"] < 100:
        s = 0
    scores.append(("网关", s, 15))
    if g["avg"] is not None:
        details.append(f"网关 {g['avg']} ms / 丢包 {g['loss_pct']}%")
        if g["avg"] > 10:
            advice.append("网关延迟偏高 — 检查路由器位置和 WiFi 信号")
        if g["loss_pct"] > 2:
            advice.append("网关存在丢包 — 优先检查 WiFi 信号和路由器")
    else:
        details.append("网关不可达")
        advice.append("网关不可达 — 检查网线/WiFi 连接")

    b = nl.ping_stats("www.baidu.com", 4)
    s2 = _score_linear(b["avg"], 30, 150, 15) + (10 if b["loss_pct"] == 0 else (5 if b["loss_pct"] <= 2 else 0))
    scores.append(("外网", min(s2, 25), 25))
    if b["avg"] is not None:
        details.append(f"百度 {b['avg']} ms / 丢包 {b['loss_pct']}%")
        if b["avg"] > 80:
            advice.append("外网延迟偏高 — 可能是宽带高峰期, 建议重启光猫/路由器")
        if b["loss_pct"] > 0:
            advice.append("外网丢包 — 运行 'auto' 做一次全面优化")
    else:
        details.append("外网不可达")
        advice.append("外网完全不可达 — 联系运营商排查宽带线路")

    dns_servers = nl.current_dns() or ["223.5.5.5"]
    dn = [nl.dns_query(d, "www.baidu.com") for d in dns_servers[:2]]
    dn = [t for t in dn if t is not None]
    d_avg = sum(dn) / len(dn) if dn else None
    s3 = _score_linear(d_avg, 30, 200, 20)
    scores.append(("DNS", s3, 20))
    if d_avg is not None:
        details.append(f"DNS 解析 {d_avg:.0f} ms")
        if d_avg > 100:
            advice.append(f"DNS 解析偏慢 ({d_avg:.0f} ms) — 运行 'fix dns' 切换为公共 DNS")
    else:
        details.append("DNS 解析失败")
        advice.append("DNS 解析失败 — 立即运行 'fix dns'")

    t = nl.http_ttfb("www.baidu.com")
    s4 = _score_linear(t, 150, 1000, 20)
    scores.append(("HTTP", s4, 20))
    if t is not None:
        details.append(f"百度 HTTPS {t:.0f} ms")
        if t > 500:
            advice.append("HTTP 响应慢 — 检查是否被限速或路由器老化")
    else:
        details.append("HTTP 连接失败")
        advice.append("HTTPS 连接失败 — 检查防火墙/代理设置")

    m = nl.mtu_probe()
    # MTU 越大越好, 取负翻转后套用"越小越好"的线性评分
    s5 = _score_linear(-m, -1472, -1200, 10) if m else 0
    scores.append(("MTU", s5, 10))
    details.append(f"MTU {m if m else '未知'}")
    if m and m < 1400:
        advice.append(f"MTU 偏低 ({m}) — 部分大包传输异常, 可尝试调整路由器 MTU 为 1492")

    total = sum(s for _, s, _ in scores)
    max_total = sum(w for _, _, w in scores)
    total = round(total / max_total * 100)

    # 输出
    for label, s, w in scores:
        bar = "█" * max(1, round(s / w * 20))
        pad = "░" * max(0, 20 - len(bar))
        color = nl.green if s / w >= 0.8 else (nl.yellow if s / w >= 0.5 else nl.red)
        print(f"  {label:<5} {color(bar + pad)} {s:>2}/{w}")
    for d in details:
        print(f"         {d}")
    print()
    grade = "优" if total >= 85 else ("良" if total >= 70 else ("中" if total >= 50 else "差"))
    if total >= 85:
        tcolor = nl.green
    elif total >= 70:
        tcolor = nl.yellow
    elif total >= 50:
        tcolor = nl.yellow
    else:
        tcolor = nl.red
    print(f"  健康总分: {tcolor(nl.bold(f'{total} 分'))}  评级: {tcolor(nl.bold(grade))}")

    if advice:
        print(nl.bold("\n  优化建议:"))
        for a in advice:
            print(f"  · {nl.yellow(a)}")
    else:
        print(nl.green("\n  一切正常, 保持现状即可"))

    # 历史记录与趋势
    hist = nl.hist_load().get("entries", [])
    hist_add = {"cmd": "health", "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "score": total, "detail": details}
    nl.hist_add(hist_add)
    prev = [e for e in hist if e.get("cmd") == "health" and e.get("score") is not None][-3:]
    if prev:
        last = prev[-1]["score"]
        delta = total - last
        if delta > 0:
            trend = nl.green(f"↑ +{delta}")
        elif delta < 0:
            trend = nl.red(f"↓ {delta}")
        else:
            trend = nl.yellow("→ 持平")
        print(f"  上次评分 {last} 分  本次 {total} 分  {trend}")
    nl.log(f"health: {total} 分 评级 {grade}")
