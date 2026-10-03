# -*- coding: utf-8 -*-
"""健康评分 —— 五维打分 → 0-100 总分 → 评级 / 建议 / 历史趋势。

三层结构（BRIEF §5）::

    探测    ``cmd_health`` 调 :mod:`netopt.probes`（唯一碰 IO 的地方）
    数据    ``score_*`` / ``total_score`` / ``grade`` —— 纯函数，只看传入的领域数据
    渲染    ``describe_*`` / ``render_report`` —— 纯函数，返回文本行，不 print

测试可以拿构造的 ``PingStat`` / ``MtuResult`` 直接钉评分边界与文案，
不需要执行任何系统命令。
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass

from netopt import platform, probes, state, ui
from netopt.models import MtuResult, PingStat
from netopt.platform import Runner

# 权重：保持旧版 15/25/20/20/10（合计 90），总分按 max_total 归一化到 100 分。
WEIGHT_GATEWAY = 15
WEIGHT_WAN = 25
WEIGHT_DNS = 20
WEIGHT_HTTP = 20
WEIGHT_MTU = 10

WAN_HOST = "www.baidu.com"
DNS_TEST_HOST = "www.baidu.com"
HTTP_HOST = "www.baidu.com"

# 网关评分档位（D8 的重写规则）
GW_DELAY_PERFECT_MS = 5.0  # <= 此延迟满分
GW_DELAY_POOR_MS = 50.0  # >= 此延迟 0 分
GW_LOSS_TOLERANCE_PCT = 2.0  # 局域网允许的丢包上限
GW_LOSS_UNUSABLE_PCT = 50.0  # >= 此丢包视为链路基本不可用

# 外网评分档位（与旧实现一致）
WAN_DELAY_PERFECT_MS = 30.0
WAN_DELAY_POOR_MS = 150.0

# DNS / HTTP 评分档位（与旧实现一致）
DNS_PERFECT_MS = 30.0
DNS_POOR_MS = 200.0
HTTP_PERFECT_MS = 150.0
HTTP_POOR_MS = 1000.0

# MTU 评分档位（D6）：满分门槛是 **MTU 本体** 1500，不是 payload 1472。
MTU_STANDARD = 1500  # 标准以太网
MTU_PPPOE = 1492  # 1500 - 8(PPPoE 头)，国内宽带最常见
MTU_LOW = 1400  # 低于此值对大包影响明显
MTU_SCORE_PPPOE = 8
MTU_SCORE_LOW = 5

# 探测不到的网关：PingStat 里 avg_ms=None 表示一个回复都没收到（不可达）。
_UNREACHABLE_GATEWAY = PingStat(target="", loss_pct=100.0, replies=0)


@dataclass(frozen=True)
class ItemScore:
    """一个评分维度的结果（纯数据，无行为）。"""

    label: str
    score: int
    weight: int
    detail: str


# ---------------------------------------------------------------------------
# 评分（纯函数：不碰 IO、不调 probes、不 print）
# ---------------------------------------------------------------------------
def score_linear(value: float | None, perfect: float, poor: float, max_score: int) -> int:
    """「越小越好」的线性评分：value<=perfect 满分，>=poor 0 分，中间线性。

    ``value`` 为 None（没有测量值）得 0 分。
    """
    if value is None:
        return 0
    if value <= perfect:
        return max_score
    if value >= poor:
        return 0
    ratio = (poor - value) / (poor - perfect)
    return round(max_score * ratio)


def score_gateway(stat: PingStat) -> int:
    """网关评分（满分 15）= 延迟分 × 丢包折扣。

    规则（D8：旧实现「丢包 2%~100% 先 +5 再被下一行清零」是意图读不出的死代码，
    这里重写成明确的两段）：

    - 延迟分：avg<=5ms 满 15；>=50ms 0 分；中间线性；不可达(None) 0 分。
    - 丢包折扣：
        * ``loss <= 2%``           → 保留延迟分（局域网允许轻微抖动）
        * ``2% < loss < 50%``      → 延迟分减半（链路明显异常，但仍可勉强使用）
        * ``loss >= 50%``（含 100% 不可达）→ 0 分（链路基本不可用）
    """
    delay = score_linear(stat.avg_ms, GW_DELAY_PERFECT_MS, GW_DELAY_POOR_MS, WEIGHT_GATEWAY)
    if stat.loss_pct <= GW_LOSS_TOLERANCE_PCT:
        return delay
    if stat.loss_pct < GW_LOSS_UNUSABLE_PCT:
        return delay // 2
    return 0


def score_wan(stat: PingStat) -> int:
    """外网评分（满分 25）= 延迟分(0-15) + 丢包奖励(0/5/10)。与旧实现一致。"""
    delay = score_linear(stat.avg_ms, WAN_DELAY_PERFECT_MS, WAN_DELAY_POOR_MS, 15)
    if stat.loss_pct == 0:
        bonus = 10
    elif stat.loss_pct <= 2:
        bonus = 5
    else:
        bonus = 0
    return delay + bonus


def dns_average(latencies: Sequence[float | None]) -> float | None:
    """成功查询的平均耗时（毫秒）；一个都没成功时返回 None。"""
    ok = [t for t in latencies if t is not None]
    return sum(ok) / len(ok) if ok else None


def score_dns(latencies: Sequence[float | None]) -> int:
    """DNS 评分（满分 20）：<=30ms 满分，>=200ms 0 分，中间线性；全部失败 0 分。"""
    return score_linear(dns_average(latencies), DNS_PERFECT_MS, DNS_POOR_MS, WEIGHT_DNS)


def score_http(ttfb_ms: float | None) -> int:
    """HTTP 评分（满分 20）：<=150ms 满分，>=1000ms 0 分；失败 0 分。"""
    return score_linear(ttfb_ms, HTTP_PERFECT_MS, HTTP_POOR_MS, WEIGHT_HTTP)


def score_mtu(result: MtuResult) -> int:
    """MTU 评分（满分 10），门槛用 **MTU 本体**（D6）。

    旧实现 ``_score_linear(-m, -1472, -1200, 10)`` 把 payload 值(1472)当 MTU 用，
    本机 PPPoE 1492 因此拿满分 10/10 —— 而 PPPoE 正是「大包卡顿」的常见成因，
    工具却给绿灯。新的分档：

    - ``>= 1500``（标准以太网）          → 10
    - ``1492..1499``（PPPoE 拨号等）     → 8   ← 本机 1492 落在这里，不再满分
    - ``1400..1491``（偏低）             → 5
    - ``< 1400``（严重偏低）或探测失败   → 0

    ``verified`` 只影响文案，不影响分数。
    """
    mtu = result.mtu
    if mtu is None:
        return 0
    if mtu >= MTU_STANDARD:
        return WEIGHT_MTU
    if mtu >= MTU_PPPOE:
        return MTU_SCORE_PPPOE
    if mtu >= MTU_LOW:
        return MTU_SCORE_LOW
    return 0


def total_score(items: Sequence[ItemScore]) -> int:
    """各维度得分按权重归一化到 100 分（旧版 max_total=90 的算法，保留）。"""
    max_total = sum(item.weight for item in items)
    if max_total <= 0:
        return 0
    return round(sum(item.score for item in items) / max_total * 100)


def grade(total: int) -> str:
    """评级：优 >=85 / 良 >=70 / 中 >=50 / 差。与旧实现一致。"""
    if total >= 85:
        return "优"
    if total >= 70:
        return "良"
    if total >= 50:
        return "中"
    return "差"


# ---------------------------------------------------------------------------
# 渲染（纯函数：返回文本行，不做 IO、不调 probes）
# ---------------------------------------------------------------------------
def describe_gateway(stat: PingStat) -> tuple[str, list[str]]:
    """网关明细与建议。"""
    if stat.avg_ms is None:
        return "网关不可达", ["网关不可达 — 检查网线/WiFi 连接"]
    detail = f"网关 {ui.ms(stat.avg_ms)} ms / 丢包 {ui.ms(stat.loss_pct)}%"
    advice: list[str] = []
    if stat.avg_ms > 10:
        advice.append("网关延迟偏高 — 检查路由器位置和 WiFi 信号")
    if stat.loss_pct > GW_LOSS_TOLERANCE_PCT:
        advice.append("网关存在丢包 — 优先检查 WiFi 信号和路由器")
    return detail, advice


def describe_wan(stat: PingStat) -> tuple[str, list[str]]:
    """外网明细与建议。"""
    if stat.avg_ms is None:
        return "外网不可达", ["外网完全不可达 — 联系运营商排查宽带线路"]
    detail = f"百度 {ui.ms(stat.avg_ms)} ms / 丢包 {ui.ms(stat.loss_pct)}%"
    advice: list[str] = []
    if stat.avg_ms > 80:
        advice.append("外网延迟偏高 — 可能是宽带高峰期, 建议重启光猫/路由器")
    if stat.loss_pct > 0:
        advice.append("外网丢包 — 运行 'auto' 做一次全面优化")
    return detail, advice


def describe_dns(
    latencies: Sequence[float | None], servers: Sequence[str]
) -> tuple[str, list[str]]:
    """DNS 明细与建议。

    ``servers`` 为空说明没拿到任何**真实**配置。旧实现此时拿 223.5.5.5 顶替去测
    （D3：测的不是用户真实 DNS 却照样给分），新实现如实报「未获取到 DNS 配置」。
    """
    if not servers:
        return "未获取到 DNS 配置", ["未获取到 DNS 配置 — 运行 'fix dns' 检查/设置 DNS"]
    avg = dns_average(latencies)
    if avg is None:
        return "DNS 解析失败", ["DNS 解析失败 — 立即运行 'fix dns'"]
    detail = f"DNS 解析 {avg:.0f} ms"
    advice = [f"DNS 解析偏慢 ({avg:.0f} ms) — 运行 'fix dns' 切换为公共 DNS"] if avg > 100 else []
    return detail, advice


def describe_http(ttfb_ms: float | None) -> tuple[str, list[str]]:
    """HTTP 明细与建议。"""
    if ttfb_ms is None:
        return "HTTP 连接失败", ["HTTPS 连接失败 — 检查防火墙/代理设置"]
    detail = f"百度 HTTPS {ui.ms(ttfb_ms)} ms"
    advice = ["HTTP 响应慢 — 检查是否被限速或路由器老化"] if ttfb_ms > 500 else []
    return detail, advice


def describe_mtu(result: MtuResult) -> tuple[str, list[str]]:
    """MTU 明细与建议：如实标注档位，``verified=False`` 时注明「探测未经确认」。"""
    mtu = result.mtu
    if mtu is None:
        return "MTU 未知（探测失败）", ["MTU 探测失败 — 目标不可达或路径不稳定, 可稍后重试"]
    advice: list[str] = []
    if mtu >= MTU_STANDARD:
        detail = f"MTU {mtu}（标准以太网）"
    elif mtu == MTU_PPPOE:
        detail = f"MTU {mtu}（PPPoE 拨号线路）"
        advice.append(
            f"MTU {MTU_PPPOE} 为 PPPoE 拨号线路 — 大包易卡顿，建议确认路由器已开启 MSS 钳制"
        )
    elif mtu > MTU_PPPOE:
        detail = f"MTU {mtu}（低于标准 {MTU_STANDARD}）"
        advice.append(f"MTU {mtu} 未达标准 {MTU_STANDARD} — 若遇到大包卡顿可检查路由器 MTU 设置")
    elif mtu >= MTU_LOW:
        detail = f"MTU {mtu}（偏低）"
        advice.append(f"MTU 偏低 ({mtu}) — 部分大包传输异常, 可尝试调整路由器 MTU 为 1492")
    else:
        detail = f"MTU {mtu}（严重偏低）"
        advice.append(f"MTU 严重偏低 ({mtu}) — 大包传输会明显异常, 检查 VPN/隧道或路由器 MTU 设置")
    if not result.verified:
        detail += "（探测未经确认）"
    return detail, advice


def render_report(
    items: Sequence[ItemScore],
    advice: Sequence[str],
    prev_score: int | None = None,
) -> list[str]:
    """把评分结果渲染成待打印的文本行（纯函数，不含任何 IO）。

    版式与旧实现一致：标题 → 每项进度条 → 每项明细 → 总分/评级 → 建议 → 趋势。
    """
    total = total_score(items)
    rank = grade(total)
    lines = [ui.bold("== 健康评分 ==")]

    for item in items:
        ratio = item.score / item.weight if item.weight else 0.0
        if ratio >= 0.8:
            color = ui.green
        elif ratio >= 0.5:
            color = ui.yellow
        else:
            color = ui.red
        lines.append(f"  {item.label:<5} {color(ui.bar(ratio))} {item.score:>2}/{item.weight}")
    lines.extend(f"         {item.detail}" for item in items)

    if total >= 85:
        tcolor = ui.green
    elif total >= 50:
        tcolor = ui.yellow
    else:
        tcolor = ui.red
    lines.append("")
    lines.append(f"  健康总分: {tcolor(ui.bold(f'{total} 分'))}  评级: {tcolor(ui.bold(rank))}")

    lines.append("")
    if advice:
        lines.append(ui.bold("  优化建议:"))
        lines.extend(f"  · {ui.yellow(a)}" for a in advice)
    else:
        lines.append(ui.green("  一切正常, 保持现状即可"))

    if prev_score is not None:
        delta = total - prev_score
        if delta > 0:
            trend = ui.green(f"↑ +{delta}")
        elif delta < 0:
            trend = ui.red(f"↓ {delta}")
        else:
            trend = ui.yellow("→ 持平")
        lines.append(f"  上次评分 {prev_score} 分  本次 {total} 分  {trend}")
    return lines


# ---------------------------------------------------------------------------
# 编排：探测 → 评分/渲染 → 打印 → 记录历史
# ---------------------------------------------------------------------------
def _dns_servers_to_test(run: Runner) -> list[str]:
    """要实测的 DNS 服务器：优先默认路由接口上的配置，其次全部接口的配置。

    - 只认 IPv4：``dns_query`` 走 AF_INET，IPv6 地址测不了，混进来只会得到
      「解析失败」的假结论；
    - 去重、最多测 2 个（与旧实现一致）；
    - **绝不**在拿不到真实配置时用 223.5.5.5 顶替（旧实现的 D3 行为：测的不是
      用户真实 DNS 却照样给分）。
    """
    configs = probes.dns_config(run)
    primary = {iface.name for iface in probes.primary_interfaces(run)}
    servers: list[str] = []
    for cfg in configs:
        if cfg.interface in primary:
            servers.extend(cfg.servers)
    if not servers:
        for cfg in configs:
            servers.extend(cfg.servers)
    return [s for s in dict.fromkeys(servers) if ":" not in s][:2]


def _last_health_score() -> int | None:
    """最近一次 health 评分（**必须在 hist_add 之前**调用，否则会读到本次）。"""
    entries = state.hist_load().get("entries", [])
    if not isinstance(entries, list):
        return None
    for entry in reversed(entries):
        if isinstance(entry, dict) and entry.get("cmd") == "health":
            score = entry.get("score")
            if isinstance(score, int):
                return score
    return None


def cmd_health(run: Runner | None = None) -> None:
    """健康评分入口：探测 → 评分/渲染（纯函数）→ 打印 → 记录历史。"""
    run = run if run is not None else platform.run

    # ---- 探测（唯一碰 IO 的地方，命令一律走注入的 runner）----
    gw = probes.gateway(run)
    gw_stat = probes.ping(gw.ip, count=4, run=run) if gw is not None else _UNREACHABLE_GATEWAY
    wan_stat = probes.ping(WAN_HOST, count=4, run=run)
    servers = _dns_servers_to_test(run)
    dns_times = [probes.dns_query(server, DNS_TEST_HOST) for server in servers]
    http_ms = probes.http_ttfb(HTTP_HOST)
    mtu_result = probes.mtu(run=run)

    # ---- 评分 + 渲染 ----
    items: list[ItemScore] = []
    advice: list[str] = []

    def add(label: str, score: int, weight: int, described: tuple[str, list[str]]) -> None:
        detail, tips = described
        items.append(ItemScore(label=label, score=score, weight=weight, detail=detail))
        advice.extend(tips)

    add("网关", score_gateway(gw_stat), WEIGHT_GATEWAY, describe_gateway(gw_stat))
    add("外网", score_wan(wan_stat), WEIGHT_WAN, describe_wan(wan_stat))
    add("DNS", score_dns(dns_times), WEIGHT_DNS, describe_dns(dns_times, servers))
    add("HTTP", score_http(http_ms), WEIGHT_HTTP, describe_http(http_ms))
    add("MTU", score_mtu(mtu_result), WEIGHT_MTU, describe_mtu(mtu_result))

    # 先读历史再写入：prev 不能包含本次（旧实现的顺序是对的，别搞反）。
    prev_score = _last_health_score()
    for line in render_report(items, advice, prev_score):
        print(line)

    total = total_score(items)
    state.hist_add(
        {
            "cmd": "health",
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "score": total,
            "detail": [item.detail for item in items],
        }
    )
    state.log(f"health: {total} 分 评级 {grade(total)}")
