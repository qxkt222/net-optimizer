# -*- coding: utf-8 -*-
"""健康评分 —— 领域数据 + Policy → :class:`Score` 与 :class:`Finding`。

对应 v1 ``netopt/health.py`` 的**评分**部分（T3.8 迁移）。本模块是纯函数层：
不读写文件、不执行子进程、不打印，也不依赖 probes / platform / ui。
探测结果由调用方传入，阈值与权重全部来自
:class:`~netopt.domain.policy.Policy`。

与 v1 对齐的规则（默认 Policy 下逐位一致）：

- 五项权重 15/25/20/20/10，总分 ``round(得分和 / 权重和 * 100)``；
- 延迟类维度「good 满分、poor 0 分、中间线性」，``None`` 记 0 分；
- 网关丢包按 ``tolerate`` / ``unusable`` 两段打折；
- 外网 = 延迟分（60% 权重）+ 丢包奖励（40% 权重），默认权重 25 时即
  15 + 10（奖励档 0% → 10，≤tolerate → 5）。

有意的行为差异（修 v1 的 D3 缺陷）：**没有配置任何 DNS 服务器时不参与
打分**，只产出 ``DNS_NO_CONFIG``，不再拿公共 DNS 顶替出一个分数。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from netopt.domain import (
    DEFAULT_WEIGHTS,
    Finding,
    FindingCode,
    Policy,
    Score,
    Severity,
)
from netopt.models import MtuResult, PingStat

# 外网满分的 60% 给延迟、40% 给丢包奖励；默认权重 25 时即 15 + 10，
# 奖励档位 0 / 5 / 10。按权重缩放，避免自定义权重时「得分 > 满分」。
WAN_BONUS_RATIO = 0.4

# MTU 中间档占满分档的比例；默认权重 10 时即 8 / 5。同样按权重缩放。
MTU_PPPOE_RATIO = 0.8
MTU_LOW_RATIO = 0.5

# 没有默认网关时的替代数据：等价于「一个回复都没收到」。
_UNREACHABLE_GATEWAY = PingStat(target="", loss_pct=100.0, replies=0)


@dataclass(frozen=True)
class ItemScore:
    """一个评分维度的结果（纯数据，无行为）。"""

    label: str
    score: int
    weight: int
    detail: str


# ---------------------------------------------------------------------------
# 纯评分原语
# ---------------------------------------------------------------------------
def _weight(policy: Policy, key: str) -> int:
    """取某项权重；自定义 Policy 缺项时回落到 v1 默认值，避免 KeyError。"""
    return policy.weights.get(key, DEFAULT_WEIGHTS[key])


def _linear(value: float | None, good: float, poor: float, max_score: int) -> int:
    """「越小越好」的线性分：``value<=good`` 满分，``>=poor`` 0 分，中间线性。

    ``value`` 为 None（没有测量值）得 0 分。``Policy.Band`` 保证
    ``good < poor``，因此分母恒为正。
    """
    if value is None:
        return 0
    if value <= good:
        return max_score
    if value >= poor:
        return 0
    return round(max_score * (poor - value) / (poor - good))


def _dns_average(latencies: Sequence[float | None]) -> float | None:
    """成功查询的平均耗时（毫秒）；一个都没成功时返回 None。"""
    ok = [t for t in latencies if t is not None]
    return sum(ok) / len(ok) if ok else None


def score_gateway(stat: PingStat, policy: Policy) -> int:
    """网关评分（满分 = Policy 的 gateway 权重）：延迟分 × 丢包折扣。

    - 延迟分：``<= gateway.good`` 满分，``>= gateway.poor`` 0 分，中间线性。
    - 丢包折扣：``<= loss.tolerate`` 保留；``tolerate`` 与 ``unusable`` 之间
      减半（整数除法）；``>= loss.unusable``（含 100% 不可达）归零。
    """
    delay = _linear(
        stat.avg_ms,
        policy.gateway.good,
        policy.gateway.poor,
        _weight(policy, "gateway"),
    )
    if stat.loss_pct <= policy.loss.tolerate:
        return delay
    if stat.loss_pct < policy.loss.unusable:
        return delay // 2
    return 0


def score_wan(stat: PingStat, policy: Policy) -> int:
    """外网评分（满分 = Policy 的 wan 权重）= 延迟分（60%）+ 丢包奖励（40%）。

    两部分都按权重缩放：``bonus_full = round(weight * 0.4)``，
    ``delay_full = weight - bonus_full``。默认权重 25 时即 15 + 10，
    奖励档位为 0 / 5 / 10，与 v1 逐位一致。
    """
    weight = _weight(policy, "wan")
    bonus_full = round(weight * WAN_BONUS_RATIO)
    delay_full = weight - bonus_full
    delay = _linear(stat.avg_ms, policy.wan.good, policy.wan.poor, delay_full)
    if stat.loss_pct == 0:
        bonus = bonus_full
    elif stat.loss_pct <= policy.loss.tolerate:
        bonus = bonus_full // 2
    else:
        bonus = 0
    return delay + bonus


def score_dns(latencies: Sequence[float | None], policy: Policy) -> int:
    """DNS 评分（满分 = Policy 的 dns 权重）：成功查询的平均耗时线性计分。

    全部查询失败（没有成功值）记 0 分。
    """
    average = _dns_average(latencies)
    return _linear(average, policy.dns.good, policy.dns.poor, _weight(policy, "dns"))


def score_http(ttfb_ms: float | None, policy: Policy) -> int:
    """HTTP 评分（满分 = Policy 的 http 权重）：首字节耗时线性计分。"""
    return _linear(
        ttfb_ms,
        policy.http_ttfb.good,
        policy.http_ttfb.poor,
        _weight(policy, "http"),
    )


def score_mtu(result: MtuResult, policy: Policy) -> int:
    """MTU 评分（满分 = Policy 的 mtu 权重），门槛是 MTU 本体。

    - ``>= mtu.standard``（标准以太网）        → 满分
    - ``>= mtu.pppoe``（PPPoE 拨号）           → 80% 满分
    - ``>= mtu.low``（偏低）                   → 50% 满分
    - 更低或探测失败（``None``）               → 0

    中间档按 mtu 权重缩放（默认权重 10 时即 8 / 5），自定义权重时不会
    出现「中间档得分 > 满分」。``verified`` 只影响文案与
    ``MTU_UNVERIFIED`` 结论，不影响分数。
    """
    mtu = result.mtu
    if mtu is None:
        return 0
    weight = _weight(policy, "mtu")
    if mtu >= policy.mtu.standard:
        return weight
    if mtu >= policy.mtu.pppoe:
        return round(weight * MTU_PPPOE_RATIO)
    if mtu >= policy.mtu.low:
        return round(weight * MTU_LOW_RATIO)
    return 0


def total_score(items: Sequence[ItemScore]) -> int:
    """各维度得分按权重归一化到 100 分（v1 的 max_total 算法，保留）。"""
    max_total = sum(item.weight for item in items)
    if max_total <= 0:
        return 0
    return round(sum(item.score for item in items) / max_total * 100)


def grade(total: int) -> str:
    """评级：优 >=85 / 良 >=70 / 中 >=50 / 差。与 v1 一致。"""
    if total >= 85:
        return "优"
    if total >= 70:
        return "良"
    if total >= 50:
        return "中"
    return "差"


# ---------------------------------------------------------------------------
# 明细文案（纯格式化，不产出结论）
# ---------------------------------------------------------------------------
def _gateway_detail(stat: PingStat) -> str:
    if stat.avg_ms is None:
        return "网关不可达"
    return f"网关 {stat.avg_ms:.1f} ms / 丢包 {stat.loss_pct:.1f}%"


def _wan_detail(stat: PingStat) -> str:
    if stat.avg_ms is None:
        return "外网不可达"
    return f"外网 {stat.avg_ms:.1f} ms / 丢包 {stat.loss_pct:.1f}%"


def _dns_detail(average: float | None) -> str:
    return "DNS 解析失败" if average is None else f"DNS 解析 {average:.0f} ms"


def _http_detail(ttfb_ms: float | None) -> str:
    return "HTTP 连接失败" if ttfb_ms is None else f"HTTP 首字节 {ttfb_ms:.0f} ms"


def _mtu_detail(result: MtuResult, policy: Policy) -> str:
    mtu = result.mtu
    if mtu is None:
        return "MTU 未知（探测失败）"
    if mtu >= policy.mtu.standard:
        return f"MTU {mtu}（标准以太网）"
    if mtu == policy.mtu.pppoe:
        return f"MTU {mtu}（PPPoE 拨号线路）"
    if mtu > policy.mtu.pppoe:
        return f"MTU {mtu}（低于标准 {policy.mtu.standard}）"
    if mtu >= policy.mtu.low:
        return f"MTU {mtu}（偏低）"
    return f"MTU {mtu}（严重偏低）"


# ---------------------------------------------------------------------------
# 结论组装
# ---------------------------------------------------------------------------
def _finding(
    code: FindingCode,
    severity: Severity,
    title: str,
    detail: str,
    advice: list[str],
) -> Finding:
    """组装一条 Finding；``code`` 一律取常量，禁止裸字符串。"""
    return Finding(
        code=code.value,
        severity=severity,
        title=title,
        detail=detail,
        advice=advice,
    )


def evaluate(
    *,
    gateway: PingStat | None,
    wan: PingStat,
    dns_latencies: Sequence[float | None],
    dns_servers: Sequence[str],
    http_ttfb: float | None,
    mtu: MtuResult,
    policy: Policy | None = None,
) -> tuple[Score, list[Finding]]:
    """把一次健康探测的结果折算成 :class:`Score` 与诊断结论。

    ``gateway=None`` 表示没有发现默认网关；``dns_servers`` 为空表示没有拿到
    任何真实 DNS 配置 —— 此时 DNS 不参与打分（``Score.items`` 里没有 DNS
    一项，权重和随之变小），只产出一条 ``DNS_NO_CONFIG`` 警告。

    同一故障只报一次：链路完全不可达时不再重复报丢包/延迟，避免同因多告警。
    """
    pol = policy if policy is not None else Policy.default()
    items: list[ItemScore] = []
    findings: list[Finding] = []

    # ---- 网关 ----
    gw_stat = gateway if gateway is not None else _UNREACHABLE_GATEWAY
    gw_detail = "未发现默认网关" if gateway is None else _gateway_detail(gw_stat)
    items.append(ItemScore("网关", score_gateway(gw_stat, pol), _weight(pol, "gateway"), gw_detail))

    if gateway is None:
        findings.append(
            _finding(
                FindingCode.GATEWAY_UNREACHABLE,
                Severity.critical,
                "未发现默认网关",
                "路由表中没有可用的 IPv4 默认网关，无法测试局域网链路",
                ["检查网线/WiFi 是否已连接并获取到 IP 地址", "重启路由器后重新运行健康检查"],
            )
        )
    elif gw_stat.avg_ms is None:
        findings.append(
            _finding(
                FindingCode.GATEWAY_UNREACHABLE,
                Severity.critical,
                "网关不可达",
                f"网关 {gw_stat.target or '未知'} 无 ping 回复（丢包 {gw_stat.loss_pct:.0f}%）",
                ["检查网线/WiFi 连接与路由器电源状态", "WiFi 环境下靠近路由器或改用有线连接后重测"],
            )
        )
    else:
        if gw_stat.loss_pct > pol.loss.tolerate:
            severity = Severity.critical if gw_stat.loss_pct >= pol.loss.unusable else Severity.warn
            findings.append(
                _finding(
                    FindingCode.GATEWAY_LOSS,
                    severity,
                    "网关丢包",
                    f"网关丢包 {gw_stat.loss_pct:.1f}%（允许上限 {pol.loss.tolerate:g}%）",
                    [
                        "优先检查 WiFi 信号强度与路由器负载，必要时改用有线连接",
                        "重启路由器/光猫后重新运行健康检查",
                    ],
                )
            )
        if gw_stat.avg_ms > pol.gateway.warn:
            findings.append(
                _finding(
                    FindingCode.GATEWAY_LATENCY_HIGH,
                    Severity.warn,
                    "网关延迟偏高",
                    f"网关延迟 {gw_stat.avg_ms:.1f} ms（阈值 {pol.gateway.warn:g} ms）",
                    [
                        "检查路由器位置与 WiFi 信号，避免隔墙或远距离连接",
                        "关闭占满带宽的后台下载后重测",
                    ],
                )
            )

    # ---- 外网 ----
    items.append(ItemScore("外网", score_wan(wan, pol), _weight(pol, "wan"), _wan_detail(wan)))

    if wan.avg_ms is None:
        findings.append(
            _finding(
                FindingCode.WAN_UNREACHABLE,
                Severity.critical,
                "外网不可达",
                "外网目标没有 ping 回复，可能是线路中断或上游故障",
                ["确认光猫指示灯与宽带线路状态，重启光猫/路由器", "外网持续不可达时联系运营商排查"],
            )
        )
    else:
        if wan.loss_pct > 0:
            severity = Severity.critical if wan.loss_pct >= pol.loss.unusable else Severity.warn
            findings.append(
                _finding(
                    FindingCode.WAN_LOSS,
                    severity,
                    "外网丢包",
                    f"外网丢包 {wan.loss_pct:.1f}%",
                    [
                        "运行 'auto' 做一次全面优化并复测线路质量",
                        "重启光猫/路由器，避开宽带高峰期重测",
                    ],
                )
            )
        if wan.avg_ms > pol.wan.warn:
            findings.append(
                _finding(
                    FindingCode.WAN_LATENCY_HIGH,
                    Severity.warn,
                    "外网延迟偏高",
                    f"外网延迟 {wan.avg_ms:.1f} ms（阈值 {pol.wan.warn:g} ms）",
                    [
                        "可能处于宽带高峰期，稍后复测或重启光猫",
                        "检查路由器是否老化或开启了限速功能",
                    ],
                )
            )

    # ---- DNS ----
    if not dns_servers:
        findings.append(
            _finding(
                FindingCode.DNS_NO_CONFIG,
                Severity.warn,
                "未获取到 DNS 配置",
                "所有网络接口都没有读到 DNS 服务器地址，本次不参与评分",
                ["运行 'fix dns' 检查并设置 DNS 服务器", "确认接口已连接且能从 DHCP 获取到 DNS"],
            )
        )
    else:
        dns_avg = _dns_average(dns_latencies)
        items.append(
            ItemScore(
                "DNS", score_dns(dns_latencies, pol), _weight(pol, "dns"), _dns_detail(dns_avg)
            )
        )
        if dns_avg is None:
            findings.append(
                _finding(
                    FindingCode.DNS_FAIL,
                    Severity.critical,
                    "DNS 解析失败",
                    f"{len(dns_latencies)} 次查询全部失败",
                    [
                        "立即运行 'fix dns' 切换为公共 DNS（如 223.5.5.5）",
                        "检查防火墙/代理是否拦截了 UDP 53",
                    ],
                )
            )
        elif dns_avg > pol.dns.warn:
            findings.append(
                _finding(
                    FindingCode.DNS_SLOW,
                    Severity.warn,
                    "DNS 解析偏慢",
                    f"DNS 平均 {dns_avg:.0f} ms（阈值 {pol.dns.warn:g} ms）",
                    [
                        "运行 'fix dns' 切换为响应更快的公共 DNS",
                        "检查路由器是否开启了缓慢的 DNS 代理",
                    ],
                )
            )

    # ---- HTTP ----
    items.append(
        ItemScore("HTTP", score_http(http_ttfb, pol), _weight(pol, "http"), _http_detail(http_ttfb))
    )
    if http_ttfb is None:
        findings.append(
            _finding(
                FindingCode.HTTP_FAIL,
                Severity.critical,
                "HTTP 连接失败",
                "HTTPS 请求没有拿到响应",
                [
                    "检查防火墙/代理是否拦截了 HTTPS 出口",
                    "先运行 'ping' 与 'dns' 确认外网与解析正常",
                ],
            )
        )
    elif http_ttfb > pol.http_ttfb.warn:
        findings.append(
            _finding(
                FindingCode.HTTP_SLOW,
                Severity.warn,
                "HTTP 响应偏慢",
                f"HTTP 首字节 {http_ttfb:.0f} ms（阈值 {pol.http_ttfb.warn:g} ms）",
                [
                    "检查是否被限速或路由器老化，必要时重启网络设备",
                    "复测一次，排除对端服务临时变慢",
                ],
            )
        )

    # ---- MTU ----
    items.append(ItemScore("MTU", score_mtu(mtu, pol), _weight(pol, "mtu"), _mtu_detail(mtu, pol)))
    mtu_value = mtu.mtu
    if mtu_value is None:
        findings.append(
            _finding(
                FindingCode.MTU_UNKNOWN,
                Severity.warn,
                "MTU 探测失败",
                "没有测出路径 MTU，大包问题无法判断",
                [
                    "稍后重试，确认目标可达且未禁用 ICMP",
                    "也可手动用 'ping -f -l 1464' 判断路径 MTU",
                ],
            )
        )
    elif mtu_value == pol.mtu.pppoe:
        findings.append(
            _finding(
                FindingCode.MTU_PPPOE,
                Severity.info,
                "MTU 为 PPPoE 线路",
                f"MTU {mtu_value} 为 PPPoE 拨号线路（标准 {pol.mtu.standard}）",
                ["确认路由器已开启 MSS 钳制（MSS Clamping），避免大包卡顿"],
            )
        )
    elif mtu_value < pol.mtu.low:
        findings.append(
            _finding(
                FindingCode.MTU_VERY_LOW,
                Severity.critical,
                "MTU 严重偏低",
                f"MTU {mtu_value} 明显低于 {pol.mtu.low}，大包传输会异常",
                [
                    "检查 VPN/隧道或 PPPoE 设置，把 MTU 恢复到 1492 以上",
                    "逐个关闭 VPN 后复测，定位压缩 MTU 的链路",
                ],
            )
        )
    elif mtu_value < pol.mtu.pppoe:
        findings.append(
            _finding(
                FindingCode.MTU_LOW,
                Severity.warn,
                "MTU 偏低",
                f"MTU {mtu_value} 低于 PPPoE 常见值 {pol.mtu.pppoe}",
                ["将路由器 MTU 调整为 1492 后重新探测", "检查 VPN/隧道是否压缩了 MTU"],
            )
        )
    if mtu_value is not None and not mtu.verified:
        findings.append(
            _finding(
                FindingCode.MTU_UNVERIFIED,
                Severity.info,
                "MTU 探测结果未经确认",
                f"MTU {mtu_value} 的边界没有经过重复确认，仅供参考",
                ["重新运行 MTU 探测以确认边界"],
            )
        )

    total = total_score(items)
    score = Score(
        total=total,
        grade=grade(total),
        items=[
            {"label": item.label, "score": item.score, "weight": item.weight, "detail": item.detail}
            for item in items
        ],
    )
    return score, findings
