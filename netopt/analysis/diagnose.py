# -*- coding: utf-8 -*-
"""连通性归因 —— 用一张探测快照回答「问题到底出在哪一段」。

v1 的 status / health / auto 各写各的阈值，同一次故障在不同命令里会得到
不同的结论。本模块把判断收敛成**一条归因链**：从最靠近本机的网段开始，
逐段检查，第一个失败的网段就是结论，下游不再重复报：

1. 没有默认网关 / 网关 ping 不通   → ``DIAG_LOCAL_LINK``（本地链路）
2. 网关丢包超过 ``loss.tolerate``  → ``DIAG_ACCESS_NETWORK``（接入网：
   WiFi 信号/信道、网线、路由器）
3. 网关正常但外网不可达或丢包      → ``DIAG_ISP_BACKBONE``（运营商/骨干）
4. 网关与外网正常但 DNS 失败或偏慢 → ``DIAG_DNS``（DNS 选型）
5. 前三段正常但 HTTP 失败或偏慢    → ``DIAG_APP_LAYER``（代理/防火墙/目标站点）
6. 全部正常但 TCP 重传偏高         → ``DIAG_TCP_RETRANSMIT``（线路质量/驱动）

「同一根因只报一条」是硬约束：网关不可达时不会再报外网丢包，外网不可达时
不会再报 DNS —— 下游现象都是同一根因的后果，重复报只会淹没真正的结论。
全部正常时返回空列表，不硬造结论。

阈值全部来自 :class:`~netopt.domain.policy.Policy`，唯一的例外是
``TCP_RETRANSMIT_WARN``（见常量注释）：TCP 重传是可选输入，Policy 里没有
对应字段，而改 ``policy.py`` 不在本模块的职责范围内。

纯函数：只读快照与 Policy，不探测、不读写文件、不打印。
"""

from __future__ import annotations

from dataclasses import dataclass

from netopt.domain import Finding, FindingCode, Policy, Severity
from netopt.models import MtuResult, PingStat

#: 每连接 TCP 重传次数阈值。健康链路上单个连接通常为 0 次；偶发 1~2 次可由
#: 对端拥塞或单个丢包解释。按一个连接约 1000 个报文段估算，持续超过 3 次
#: 对应约 0.3% 以上的丢包，已经明显高于正常宽带水平，因此归因到线路质量
#: 或网卡驱动，而不是再往上游猜。超过阈值（严格大于）才报。
TCP_RETRANSMIT_WARN = 3


@dataclass(frozen=True)
class ConnectivitySnapshot:
    """一次连通性探测的原始结果，是归因链的唯一输入。

    ``gateway=None`` 表示没有找到 IPv4 默认网关；``PingStat.avg_ms is None``
    表示一个回复都没收到（不可达，``loss_pct`` 此时为 100）。``dns_servers``
    为空说明没有可测的 DNS 配置，此时 DNS 段无法判断，归因链会跳过它
    （``DNS_NO_CONFIG`` 由 ``analysis/health.py`` 单独负责）。

    ``mtu`` 与 ``tcp_retransmits`` 都是可选项：前者不参与归因（MTU 异常是
    独立结论），后者是唯一能区分「线路质量」与「应用层」的信号。
    """

    gateway: PingStat | None
    wan: PingStat
    dns_avg_ms: float | None
    dns_servers: list[str]
    http_ttfb_ms: float | None
    mtu: MtuResult | None = None
    tcp_retransmits: int | None = None


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


def _name(stat: PingStat) -> str:
    """目标显示名；没填地址时用「未知」，避免文案出现空括号。"""
    return stat.target or "未知"


def _local_link_missing() -> Finding:
    return _finding(
        FindingCode.DIAG_LOCAL_LINK,
        Severity.critical,
        "未发现默认网关",
        "路由表中没有可用的 IPv4 默认网关，连局域网第一跳都无法测试",
        [
            "检查网线是否插好，或 WiFi 是否已连接并拿到 IP 地址",
            "重启路由器/光猫后重新运行诊断",
        ],
    )


def _local_link_unreachable(gateway: PingStat) -> Finding:
    return _finding(
        FindingCode.DIAG_LOCAL_LINK,
        Severity.critical,
        "本地链路中断",
        f"网关 {_name(gateway)} 无 ping 回复（丢包 {gateway.loss_pct:.1f}%），"
        "本机到局域网第一跳已断开",
        [
            "检查网线/WiFi 连接与路由器电源、指示灯状态",
            "WiFi 环境下靠近路由器或改用有线连接后重测",
        ],
    )


def _access_network(gateway: PingStat, policy: Policy) -> Finding:
    loss = gateway.loss_pct
    severity = Severity.critical if loss >= policy.loss.unusable else Severity.warn
    return _finding(
        FindingCode.DIAG_ACCESS_NETWORK,
        severity,
        "本地接入段丢包",
        f"网关 {_name(gateway)} 可达但丢包 {loss:.1f}%"
        f"（允许上限 {policy.loss.tolerate:g}%），问题在本地接入段",
        [
            "检查 WiFi 信号强度与信道干扰，必要时改用有线连接",
            "重启路由器，排除路由器负载过高或网线接触不良",
        ],
    )


def _isp_unreachable(gateway: PingStat, wan: PingStat) -> Finding:
    return _finding(
        FindingCode.DIAG_ISP_BACKBONE,
        Severity.critical,
        "外网不可达（运营商/骨干）",
        f"网关丢包 {gateway.loss_pct:.1f}% 正常，但外网 {_name(wan)} 无 ping 回复"
        f"（丢包 {wan.loss_pct:.1f}%），本机到上游链路中断",
        [
            "查看光猫指示灯与宽带线路状态，重启光猫/路由器",
            "问题持续时联系运营商报修线路",
        ],
    )


def _isp_loss(gateway: PingStat, wan: PingStat, policy: Policy) -> Finding:
    loss = wan.loss_pct
    severity = Severity.critical if loss >= policy.loss.unusable else Severity.warn
    return _finding(
        FindingCode.DIAG_ISP_BACKBONE,
        severity,
        "外网丢包（运营商/骨干）",
        f"网关丢包 {gateway.loss_pct:.1f}% 正常，外网 {_name(wan)} 丢包 {loss:.1f}%"
        f"（允许上限 {policy.loss.tolerate:g}%），问题在运营商或骨干网",
        [
            "避开宽带高峰期复测，确认丢包是否持续存在",
            "重启光猫并检查入户线路，持续异常时联系运营商",
        ],
    )


def _dns_fail(servers: list[str]) -> Finding:
    return _finding(
        FindingCode.DIAG_DNS,
        Severity.critical,
        "DNS 解析全部失败",
        f"{len(servers)} 个 DNS 服务器（{'、'.join(servers)}）查询全部失败，而网关与外网均可达",
        [
            "运行 'fix dns' 切换为公共 DNS（如 223.5.5.5）",
            "检查防火墙/代理是否拦截了 UDP/TCP 53",
        ],
    )


def _dns_slow(dns_avg_ms: float, gateway_ms: float, wan_ms: float, policy: Policy) -> Finding:
    return _finding(
        FindingCode.DIAG_DNS,
        Severity.warn,
        "DNS 解析偏慢",
        f"DNS 平均 {dns_avg_ms:.0f} ms 超过阈值 {policy.dns.warn:g} ms"
        f"（网关 {gateway_ms:.1f} ms、外网 {wan_ms:.1f} ms 正常）",
        [
            "运行 'fix dns' 改用响应更快的公共 DNS",
            "检查路由器是否开启了缓慢的 DNS 代理/转发",
        ],
    )


def _app_fail(dns_avg_ms: float | None, gateway_ms: float, wan_ms: float) -> Finding:
    dns_text = f"DNS {dns_avg_ms:.0f} ms" if dns_avg_ms is not None else "DNS 正常"
    return _finding(
        FindingCode.DIAG_APP_LAYER,
        Severity.warn,
        "应用层请求失败",
        f"网关 {gateway_ms:.1f} ms、外网 {wan_ms:.1f} ms、{dns_text} 均正常，"
        "但 HTTPS 请求没有拿到响应",
        [
            "检查系统/浏览器代理与防火墙是否拦截 HTTPS 出口",
            "换一个目标站点复测，排除对端服务临时故障",
        ],
    )


def _app_slow(
    http_ttfb_ms: float,
    gateway_ms: float,
    wan_ms: float,
    policy: Policy,
) -> Finding:
    return _finding(
        FindingCode.DIAG_APP_LAYER,
        Severity.warn,
        "应用层响应偏慢",
        f"HTTP 首字节 {http_ttfb_ms:.0f} ms 超过阈值 {policy.http_ttfb.warn:g} ms，"
        f"而网关 {gateway_ms:.1f} ms、外网 {wan_ms:.1f} ms 正常",
        [
            "检查代理/VPN 与目标站点状态，换一个站点复测",
            "关闭后台大流量下载后重测一次",
        ],
    )


def _tcp_retransmit(retransmits: int, wan_ms: float, wan_loss: float) -> Finding:
    return _finding(
        FindingCode.DIAG_TCP_RETRANSMIT,
        Severity.warn,
        "TCP 重传偏高",
        f"外网 {wan_ms:.1f} ms / 丢包 {wan_loss:.1f}% 正常，"
        f"但每连接 TCP 重传 {retransmits} 次（阈值 {TCP_RETRANSMIT_WARN}），"
        "提示线路质量或网卡驱动异常",
        [
            "更新网卡/无线驱动并关闭网卡节能模式后复测",
            "运行 'fix tcp' 检查 TCP 参数，必要时更换网线或 WiFi 信道",
        ],
    )


def diagnose(
    snapshot: ConnectivitySnapshot,
    policy: Policy | None = None,
) -> list[Finding]:
    """按「本地 → 接入 → 骨干 → DNS → 应用 → 线路」的顺序归因。

    返回**至多一条**结论：第一个失败的网段即根因，后续网段不再检查，因此
    不会出现「网关不可达 + 外网丢包 + DNS 失败」这类同因多报。全部指标
    正常（或可选输入缺失）时返回空列表。

    判定口径（阈值均取自 ``policy``）：

    - 网关缺失或 ``gateway.avg_ms is None``      → ``DIAG_LOCAL_LINK`` critical
    - 网关 ``loss_pct > loss.tolerate``          → ``DIAG_ACCESS_NETWORK``
      （``>= loss.unusable`` 升为 critical）
    - 外网 ``avg_ms is None``                    → ``DIAG_ISP_BACKBONE`` critical
    - 外网 ``loss_pct > loss.tolerate``          → ``DIAG_ISP_BACKBONE``
      （``>= loss.unusable`` 升为 critical）
    - ``dns_servers`` 非空且 ``dns_avg_ms is None`` → ``DIAG_DNS`` critical
    - ``dns_avg_ms > dns.warn``                  → ``DIAG_DNS`` warn
    - ``http_ttfb_ms is None`` / ``> http_ttfb.warn`` → ``DIAG_APP_LAYER`` warn
    - ``tcp_retransmits > TCP_RETRANSMIT_WARN``  → ``DIAG_TCP_RETRANSMIT`` warn

    ``dns_servers`` 为空时 DNS 段不参与归因：没有配置就没有可测对象，
    硬判失败会把「没配置 DNS」误报成「DNS 故障」。

    网关/外网的**延迟**单指标不在链上：它影响体验，但不改变「问题在哪一段」
    的归属，延迟结论由 ``analysis/health.py`` 负责。
    """
    pol = policy if policy is not None else Policy.default()

    # ---- 第 1 段：本地链路 ----
    gateway = snapshot.gateway
    if gateway is None:
        return [_local_link_missing()]
    gateway_ms = gateway.avg_ms
    if gateway_ms is None:
        return [_local_link_unreachable(gateway)]
    if gateway.loss_pct > pol.loss.tolerate:
        return [_access_network(gateway, pol)]

    # ---- 第 2 段：运营商 / 骨干 ----
    wan = snapshot.wan
    wan_ms = wan.avg_ms
    if wan_ms is None:
        return [_isp_unreachable(gateway, wan)]
    if wan.loss_pct > pol.loss.tolerate:
        return [_isp_loss(gateway, wan, pol)]

    # ---- 第 3 段：DNS ----
    dns_avg_ms = snapshot.dns_avg_ms
    if snapshot.dns_servers:
        if dns_avg_ms is None:
            return [_dns_fail(snapshot.dns_servers)]
        if dns_avg_ms > pol.dns.warn:
            return [_dns_slow(dns_avg_ms, gateway_ms, wan_ms, pol)]

    # ---- 第 4 段：应用层 ----
    http_ttfb_ms = snapshot.http_ttfb_ms
    if http_ttfb_ms is None:
        return [_app_fail(dns_avg_ms, gateway_ms, wan_ms)]
    if http_ttfb_ms > pol.http_ttfb.warn:
        return [_app_slow(http_ttfb_ms, gateway_ms, wan_ms, pol)]

    # ---- 第 5 段：线路质量 / 驱动 ----
    retransmits = snapshot.tcp_retransmits
    if retransmits is not None and retransmits > TCP_RETRANSMIT_WARN:
        return [_tcp_retransmit(retransmits, wan_ms, wan.loss_pct)]

    return []


__all__ = ["TCP_RETRANSMIT_WARN", "ConnectivitySnapshot", "diagnose"]
