# -*- coding: utf-8 -*-
"""``status`` 命令 —— 探测 → 归因 → :class:`Report`（v2 垂直切片）。

职责边界：

- **只做编排与分档**：读系统走 :class:`~netopt.system.api.SystemApi`，测量走
  v2 探测层（:mod:`netopt.probes_dns` / :mod:`netopt.probes_http` /
  :mod:`netopt.probes_mtu`），阈值一律取
  :meth:`netopt.domain.policy.Policy.default`，本模块不写死任何阈值。
- **不打印**：产出 :class:`Report` 交给 ``netopt.render``；终端/JSON/GUI 三条
  路径消费同一份数据。
- **失败不吞**：所有探测失败统一写进
  :class:`~netopt.probes.ProbeContext.errors`，最后原样搬到
  ``Report.errors``；对应指标标成 ``available=False``。
- **总量受预算约束**：``budget_seconds`` 默认 20 秒（SPEC §7.1），MTU 另有
  8 秒上限。预算耗尽立刻停止后续测量并记 ``timeout``，不再把一次 ``status``
  拖到十几秒。

v1 缺陷修复：

- T3.4：DNS 的 IPv4 / IPv6 先分流，**只用 IPv4 实测**；仅配置 IPv6 DNS 时
  产出 ``DNS_IPV6_ONLY``（info），不误报 ``DNS_FAIL``。
- D1：网关改由默认路由的 ``next_hop`` 决定，不再取 ``ipconfig`` 的第一行。
- D15：MTU 走预算内二分，超预算返回 ``verified=False`` + ``ProbeError``。

归因：所有测量汇总成 :class:`~netopt.analysis.diagnose.ConnectivitySnapshot`，
交给 :func:`~netopt.analysis.diagnose.diagnose` 产出「问题在哪一段」的顶层
结论；按 ``code`` 去重且 diagnose 优先，各节自己的结论仍留在 ``Section`` 内。
"""

from __future__ import annotations

import os
import platform as sys_platform
import time
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime
from functools import partial
from ipaddress import IPv4Address, ip_address
from typing import Any, Protocol, TypeVar

from netopt import platform, probes, probes_dns, probes_http, probes_mtu
from netopt.analysis.diagnose import ConnectivitySnapshot, diagnose
from netopt.domain import (
    Band,
    Evidence,
    Finding,
    FindingCode,
    InterfaceDns,
    Metric,
    Policy,
    ProbeErrorCode,
    Report,
    Route,
    Section,
    Severity,
)
from netopt.models import PingStat
from netopt.platform import Runner
from netopt.probes import ProbeContext
from netopt.system import LiveSystemApi, SystemApi

#: 与 v1 ``diag.cmd_status`` 一致的探测目标与次数。
WAN_HOST = "www.baidu.com"
HTTP_HOST = "www.baidu.com"
PING_COUNT = 4
#: 与 v1 一致：最多实测前两台 DNS 服务器，避免 status 变慢。
DNS_PROBE_LIMIT = 2
#: 每台 DNS 服务器的查询次数（v2 取平均，减少单次抖动）。
DNS_ATTEMPTS = 3
#: MTU 单列预算（SPEC §7.1）。
MTU_BUDGET_SECONDS = 8.0

_T = TypeVar("_T")


class _PingLike(Protocol):
    """``probes.ping`` 结果的最小结构（避免命令层依赖全部 v1 模型细节）。

    用只读 property 声明：``PingStat`` 是 frozen dataclass，普通属性协议会
    因为不可写而不兼容。
    """

    @property
    def avg_ms(self) -> float | None: ...

    @property
    def loss_pct(self) -> float: ...

    @property
    def replies(self) -> int: ...


# ---------------------------------------------------------------------------
# 探测容错与预算
# ---------------------------------------------------------------------------


def _record_unavailable(ctx: ProbeContext, source: str, exc: BaseException) -> None:
    """把探测异常翻译成可解释的错误并记进上下文。"""
    message = f"{type(exc).__name__}: {exc}"[:200]
    ctx.record_error(ProbeErrorCode.UNAVAILABLE.value, source, message)


def _record_timeout(ctx: ProbeContext, source: str, message: str) -> None:
    """记录一条超时/无响应；这类失败通常换个时机重试有意义。"""
    ctx.record_error(ProbeErrorCode.TIMEOUT.value, source, message, retryable=True)


def _has_error(ctx: ProbeContext, source: str) -> bool:
    """上下文里是否已经有某个来源的错误（避免同一失败重复记录）。"""
    return any(error.source == source for error in ctx.errors)


def _guarded(
    ctx: ProbeContext,
    source: str,
    func: Callable[[], _T],
    default: _T | None = None,
) -> _T | None:
    """执行一次读系统/测量；失败记进上下文并返回 ``default``，绝不静默。

    预算已耗尽时不再启动新的测量，直接记一条 ``timeout``。
    """
    if ctx.expired():
        _record_timeout(ctx, source, "总预算已耗尽，跳过探测")
        return default
    try:
        value = func()
    except Exception as exc:  # 探测边界必须把任何失败转成数据
        _record_unavailable(ctx, source, exc)
        return default
    if ctx.expired():
        # 结果仍然可用，但如实标注本次探测越过了总预算。
        _record_timeout(ctx, source, "探测超出总预算（结果仍采用）")
    return value


def _probe_ms(ctx: ProbeContext, source: str, func: Callable[[], float | None]) -> float | None:
    """执行一次「返回毫秒或 None」的注入式探测。

    ``None`` 一律按超时记录（与 v1 的语义一致），异常按 ``unavailable``
    记录；两种情况都不让异常穿透。
    """
    if ctx.expired():
        _record_timeout(ctx, source, "总预算已耗尽，跳过探测")
        return None
    try:
        value = func()
    except Exception as exc:
        _record_unavailable(ctx, source, exc)
        return None
    if value is None:
        _record_timeout(ctx, source, f"{source} 在超时内没有响应")
        return None
    if ctx.expired():
        _record_timeout(ctx, source, "探测超出总预算（结果仍采用）")
    return value


# ---------------------------------------------------------------------------
# Metric / Finding 构造
# ---------------------------------------------------------------------------


def _latency_metric(
    key: str,
    label: str,
    value: float | None,
    band: Band,
    *,
    note: str | None = None,
) -> Metric:
    """延迟指标：``good`` / ``warn`` 直接取自 policy 的 :class:`Band`。"""
    return Metric(
        key=key,
        label=label,
        value=value,
        unit="ms",
        good=band.good,
        warn=band.warn,
        available=value is not None,
        note=note,
    )


def _loss_metric(
    key: str,
    label: str,
    value: float | None,
    policy: Policy,
    *,
    note: str | None = None,
) -> Metric:
    """丢包指标：``good`` = 可容忍上限，``warn`` = 链路不可用阈值。"""
    return Metric(
        key=key,
        label=label,
        value=value,
        unit="%",
        good=policy.loss.tolerate,
        warn=policy.loss.unusable,
        available=value is not None,
        note=note,
    )


def _ping_metrics(
    stat: _PingLike | None,
    band: Band,
    policy: Policy,
    *,
    note: str | None = None,
) -> list[Metric]:
    """把一次 ping 统计转成「延迟 + 丢包」两个指标。

    ``stat is None`` 表示探测本身失败（而非 ping 不通）：两项都标不可用，
    ``note`` 说明原因。
    """
    avg = stat.avg_ms if stat is not None else None
    loss = stat.loss_pct if stat is not None else None
    reason = note if stat is None else None
    return [
        _latency_metric("latency", "延迟", avg, band, note=reason),
        _loss_metric("loss", "丢包", loss, policy, note=reason),
    ]


def _ping_findings(
    stat: _PingLike | None,
    *,
    band: Band,
    policy: Policy,
    codes: tuple[FindingCode, FindingCode, FindingCode],
    source: str,
    label: str,
) -> list[Finding]:
    """按 policy 给一次 ping 出结论。

    - 一个回复都没有 → ``*_UNREACHABLE``（critical）；
    - 丢包超过容忍上限 → ``*_LOSS``（达到 unusable 则 critical）；
    - 平均延迟高于 ``band.warn`` → ``*_LATENCY_HIGH``，严重度取
      :meth:`Band.classify`（warn / critical）。``band.warn`` 以内不算“高”，
      不产出结论，避免正常网络里刷 info。
    """
    if stat is None:
        return []

    code_unreachable, code_loss, code_latency = codes
    findings: list[Finding] = []
    avg = stat.avg_ms
    loss = stat.loss_pct
    measured = f"平均 {avg:.1f} ms，丢包 {loss:.1f}%" if avg is not None else f"丢包 {loss:.1f}%"
    evidence = [Evidence(source=source, detail=measured)]

    if stat.replies <= 0:
        findings.append(
            Finding(
                code=code_unreachable,
                severity=Severity.critical,
                title=f"{label}不可达",
                detail=f"{PING_COUNT} 次请求全部超时，{label}没有任何回复。",
                advice=[
                    "检查网线 / WiFi 是否已连接",
                    "确认路由器 / 光猫已上电且指示灯正常",
                    f"重新运行 'ping {source.split(':', 1)[-1]}' 观察是否稳定复现",
                ],
                evidence=evidence,
            )
        )
        return findings

    if loss > policy.loss.tolerate:
        severity = Severity.critical if loss >= policy.loss.unusable else Severity.warn
        findings.append(
            Finding(
                code=code_loss,
                severity=severity,
                title=f"{label}丢包",
                detail=f"丢包率 {loss:.1f}%，超过可容忍上限 {policy.loss.tolerate:g}%。",
                advice=[
                    "更换网线或尝试有线连接，排除无线干扰",
                    "检查路由器 / 光猫是否过热或负载过高",
                ],
                evidence=evidence,
            )
        )

    if avg is not None and avg > band.warn:
        findings.append(
            Finding(
                code=code_latency,
                severity=band.classify(avg),
                title=f"{label}延迟偏高",
                detail=f"平均延迟 {avg:.1f} ms，超过关注阈值 {band.warn:g} ms。",
                advice=[
                    "关闭正在占用带宽的下载 / 视频 / 云同步",
                    "优先使用有线连接，或靠近路由器改善信号",
                ],
                evidence=evidence,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 各节
# ---------------------------------------------------------------------------


def _no_gateway_section(policy: Policy, detail: str) -> Section:
    """没有可用默认路由时的网关小节。"""
    return Section(
        id="gateway",
        title="网关",
        metrics=_ping_metrics(None, policy.gateway, policy, note="未找到默认网关"),
        findings=[
            Finding(
                code=FindingCode.GATEWAY_UNREACHABLE,
                severity=Severity.critical,
                title="未找到默认网关",
                detail=detail,
                advice=["检查网线 / WiFi 是否已连接", "确认路由器 / 光猫已上电"],
            )
        ],
    )


def _gateway_section(
    api: SystemApi,
    run: Runner,
    policy: Policy,
    ctx: ProbeContext,
) -> tuple[Section, str | None, PingStat | None]:
    """网关：默认路由的下一跳 + 延迟 / 丢包结论。

    返回 ``(小节, 网关 IP, ping 统计)``，后两项供归因快照使用。
    """
    route: Route | None = None
    read_ok = False
    try:
        route = probes.gateway_from_api(api)
        read_ok = True
    except Exception as exc:  # 读系统失败也要留下可解释的错误
        _record_unavailable(ctx, "iphlpapi", exc)

    gateway_ip = route.next_hop if route is not None else None
    if gateway_ip is None:
        detail = "无法读取默认路由，判定为未找到默认网关。"
        if read_ok:
            detail = (
                "路由表里没有可用的默认路由，可能未联网或网卡未连接。"
                if route is None
                else "默认路由存在但没有下一跳地址，无法测试局域网链路。"
            )
            ctx.record_error(ProbeErrorCode.UNAVAILABLE.value, "iphlpapi", detail)
        return _no_gateway_section(policy, detail), None, None

    stat = _guarded(
        ctx,
        f"ping:{gateway_ip}",
        lambda: probes.ping(gateway_ip, PING_COUNT, run=run),
        None,
    )
    section = Section(
        id="gateway",
        title="网关",
        metrics=_ping_metrics(stat, policy.gateway, policy, note="网关 ping 探测失败"),
        # 扁平键：渲染层按 ``ip`` / ``metric`` 映射中文标签（见 render/text.py）
        rows=[{"ip": gateway_ip, "metric": route.metric if route is not None else None}],
        findings=_ping_findings(
            stat,
            band=policy.gateway,
            policy=policy,
            codes=(
                FindingCode.GATEWAY_UNREACHABLE,
                FindingCode.GATEWAY_LOSS,
                FindingCode.GATEWAY_LATENCY_HIGH,
            ),
            source=f"ping:{gateway_ip}",
            label="网关",
        ),
    )
    return section, gateway_ip, stat


def _wan_section(
    run: Runner,
    policy: Policy,
    ctx: ProbeContext,
) -> tuple[Section, PingStat | None]:
    """外网：ping 固定目标，结论码与网关同构（``WAN_*``）。"""
    stat = _guarded(
        ctx,
        f"ping:{WAN_HOST}",
        lambda: probes.ping(WAN_HOST, PING_COUNT, run=run),
        None,
    )
    section = Section(
        id="wan",
        title="外网",
        metrics=_ping_metrics(stat, policy.wan, policy, note="外网 ping 探测失败"),
        rows=[{"target": WAN_HOST}],
        findings=_ping_findings(
            stat,
            band=policy.wan,
            policy=policy,
            codes=(
                FindingCode.WAN_UNREACHABLE,
                FindingCode.WAN_LOSS,
                FindingCode.WAN_LATENCY_HIGH,
            ),
            source=f"ping:{WAN_HOST}",
            label="外网",
        ),
    )
    return section, stat


def _collect_servers(configs: Iterable[InterfaceDns]) -> list[str]:
    """把各接口的 DNS 服务器去重保序展开（与 v1 ``collect_dns_servers`` 一致）。"""
    servers: list[str] = []
    for config in configs:
        for server in config.servers:
            if server not in servers:
                servers.append(server)
    return servers


def _split_servers(servers: Sequence[str]) -> tuple[list[str], list[str]]:
    """按地址族分流；无法解析的字符串忽略（不参与实测）。"""
    ipv4: list[str] = []
    ipv6: list[str] = []
    for server in servers:
        try:
            address = ip_address(server)
        except ValueError:
            continue
        if isinstance(address, IPv4Address):
            ipv4.append(server)
        else:
            ipv6.append(server)
    return ipv4, ipv6


def _dns_section(
    api: SystemApi,
    policy: Policy,
    ctx: ProbeContext,
    dns_probe: Callable[[str, str], float | None] | None,
) -> tuple[Section, list[str], float | None]:
    """DNS：配置 + IPv4 实测；IPv6-only 与“无配置”分开表达。

    返回 ``(小节, 实测过的服务器列表, 平均耗时)``，后两项供归因快照使用。
    """
    configs: list[InterfaceDns] = []
    read_ok = True
    try:
        configs = probes.dns_from_api(api)
    except Exception as exc:  # 探测边界：配置读取失败也要留下可解释的错误
        _record_unavailable(ctx, "iphlpapi", exc)
        read_ok = False
    servers = _collect_servers(configs)
    ipv4, ipv6 = _split_servers(servers)
    rows = [{"servers": ", ".join(servers)}] if servers else []
    findings: list[Finding] = []
    value: float | None = None
    note: str | None = None
    measured: list[str] = []

    if not servers:
        note = "未配置 DNS" if read_ok else "读取 DNS 配置失败"
        if read_ok:
            findings.append(
                Finding(
                    code=FindingCode.DNS_NO_CONFIG,
                    severity=Severity.warn,
                    title="未配置 DNS 服务器",
                    detail="所有接口都没有解析器地址，域名解析会失败（仅 IP 直连可用）。",
                    advice=["运行 'python netoptimizer.py fix dns' 写入公共 DNS"],
                    evidence=[Evidence(source="dns_config")],
                )
            )
    elif not ipv4:
        # T3.4：只有 IPv6 DNS 时不能用 IPv4 探测去测并报“解析失败”
        note = "仅配置了 IPv6 DNS，未做 IPv4 实测"
        findings.append(
            Finding(
                code=FindingCode.DNS_IPV6_ONLY,
                severity=Severity.info,
                title="仅使用 IPv6 DNS",
                detail=(
                    "检测到 IPv6 DNS 服务器但没有 IPv4 DNS："
                    f"{', '.join(ipv6)}。本次未做 IPv4 解析实测，"
                    "不代表解析失败。"
                ),
                advice=["如需在纯 IPv4 网络下解析，补充一个 IPv4 DNS 服务器"],
                evidence=[Evidence(source="dns_config", detail=", ".join(ipv6))],
            )
        )
    else:
        measured = ipv4[:DNS_PROBE_LIMIT]
        times = _dns_times(measured, ctx, dns_probe)
        value = sum(times) / len(times) if times else None
        if value is None:
            findings.append(
                Finding(
                    code=FindingCode.DNS_FAIL,
                    severity=Severity.critical,
                    title="DNS 解析失败",
                    detail=f"向 {', '.join(measured)} 查询 {WAN_HOST} 均无响应。",
                    advice=["运行 'python netoptimizer.py fix dns' 更换公共 DNS"],
                    evidence=[Evidence(source="dns", detail="全部超时")],
                )
            )
        elif value > policy.dns.warn:
            findings.append(
                Finding(
                    code=FindingCode.DNS_SLOW,
                    severity=policy.dns.classify(value),
                    title="DNS 解析偏慢",
                    detail=f"平均解析耗时 {value:.1f} ms，超过关注阈值 {policy.dns.warn:g} ms。",
                    advice=["更换更近的公共 DNS（如 223.5.5.5）"],
                    evidence=[Evidence(source="dns", detail=f"平均 {value:.1f} ms")],
                )
            )

    return (
        Section(
            id="dns",
            title="DNS",
            metrics=[_latency_metric("latency", "平均解析耗时", value, policy.dns, note=note)],
            rows=rows,
            findings=findings,
        ),
        measured,
        value,
    )


def _dns_times(
    servers: Sequence[str],
    ctx: ProbeContext,
    dns_probe: Callable[[str, str], float | None] | None,
) -> list[float]:
    """实测给定服务器的解析耗时；失败全部记进上下文。

    注入 ``dns_probe`` 时逐台查一次（保留 v1 测试语义）；否则走 v2 的
    :func:`netopt.probes_dns.benchmark`，每台查 :data:`DNS_ATTEMPTS` 次取平均，
    失败原因由它自己写进 ``ctx``。
    """
    if dns_probe is not None:
        probe = dns_probe
        times: list[float] = []
        for server in servers:
            elapsed = _probe_ms(ctx, f"dns:{server}", partial(probe, server, WAN_HOST))
            if elapsed is not None:
                times.append(elapsed)
        return times

    def _run_benchmark() -> list[probes_dns.DnsResult]:
        """对给定服务器做一轮基准查询（失败由 benchmark 自己记录）。"""
        return probes_dns.benchmark(list(servers), WAN_HOST, attempts=DNS_ATTEMPTS, ctx=ctx)

    results = _guarded(ctx, "dns", _run_benchmark)
    if not results:
        return []
    return [result.elapsed_ms for result in results if result.elapsed_ms is not None]


def _http_section(
    policy: Policy,
    ctx: ProbeContext,
    http_probe: Callable[[str], float | None] | None,
) -> tuple[Section, float | None]:
    """HTTP：HTTPS 首字节耗时（TTFB）；缺失时退回整次请求耗时。"""
    source = f"http:{HTTP_HOST}"
    ttfb: float | None = None
    if http_probe is not None:
        ttfb = _probe_ms(ctx, source, lambda: http_probe(HTTP_HOST))
    else:
        timing = _guarded(ctx, source, lambda: probes_http.measure(HTTP_HOST, ctx=ctx), None)
        if timing is not None:
            ttfb = timing.ttfb_ms if timing.ttfb_ms is not None else timing.total_ms
            if ttfb is None and timing.error is None:
                ctx.record_error(
                    ProbeErrorCode.UNAVAILABLE.value,
                    source,
                    "HTTP 测量没有拿到任何耗时",
                )

    findings: list[Finding] = []
    if ttfb is None:
        findings.append(
            Finding(
                code=FindingCode.HTTP_FAIL,
                severity=Severity.critical,
                title="HTTPS 连接失败",
                detail=f"无法完成对 {HTTP_HOST} 的 HTTPS 请求（超时或连接被拒绝）。",
                advice=["确认外网连通后再测试", "检查防火墙 / 代理设置"],
                evidence=[Evidence(source=source)],
            )
        )
    elif ttfb > policy.http_ttfb.warn:
        findings.append(
            Finding(
                code=FindingCode.HTTP_SLOW,
                severity=policy.http_ttfb.classify(ttfb),
                title="HTTPS 首字节偏慢",
                detail=f"TTFB {ttfb:.1f} ms，超过关注阈值 {policy.http_ttfb.warn:g} ms。",
                advice=["关闭占用带宽的后台程序", "尝试更换 DNS 或稍后重试"],
                evidence=[Evidence(source=source, detail=f"TTFB {ttfb:.1f} ms")],
            )
        )

    metric = Metric(
        key="ttfb",
        label="首字节耗时(TTFB)",
        value=ttfb,
        unit="ms",
        good=policy.http_ttfb.good,
        warn=policy.http_ttfb.warn,
        available=ttfb is not None,
        note=None if ttfb is not None else "HTTPS 请求失败",
    )
    return (
        Section(
            id="http",
            title="HTTP",
            metrics=[metric],
            rows=[{"target": HTTP_HOST}],
            findings=findings,
        ),
        ttfb,
    )


def _mtu_section(run: Runner, policy: Policy, ctx: ProbeContext) -> Section:
    """MTU：预算内的路径 MTU 探测与分档结论。"""
    try:
        result = probes_mtu.probe(ctx=ctx, run=run, max_seconds=MTU_BUDGET_SECONDS)
    except Exception as exc:  # 探测边界：任何异常都转成错误记录
        _record_unavailable(ctx, "mtu", exc)
        result = None

    mtu_value = result.mtu if result is not None else None
    verified = result.verified if result is not None else False

    if mtu_value is None and not _has_error(ctx, "mtu"):
        ctx.record_error(
            ProbeErrorCode.UNAVAILABLE.value,
            "mtu",
            "MTU 探测未获得确定结论（目标不可达或 ping 不可用）",
        )

    findings: list[Finding] = []
    if mtu_value is None:
        findings.append(
            Finding(
                code=FindingCode.MTU_UNKNOWN,
                severity=Severity.warn,
                title="MTU 无法确定",
                detail="DF ping 探测没有拿到确定结果，无法判断路径 MTU。",
                advice=["确认外网可达后重试", "检查防火墙是否拦截 ICMP"],
                evidence=[Evidence(source="ping -f")],
            )
        )
    else:
        evidence = [Evidence(source="ping -f", detail=f"路径 MTU {mtu_value}")]
        if mtu_value == policy.mtu.pppoe:
            findings.append(
                Finding(
                    code=FindingCode.MTU_PPPOE,
                    severity=Severity.info,
                    title="PPPoE 拨号线路 MTU",
                    detail=f"路径 MTU 为 {mtu_value}（1500 - 8），大包需要分片。",
                    advice=["PPPoE 拨号下属于正常值，无需处理"],
                    evidence=evidence,
                )
            )
        elif mtu_value < policy.mtu.low:
            findings.append(
                Finding(
                    code=FindingCode.MTU_VERY_LOW,
                    severity=Severity.warn,
                    title="路径 MTU 明显偏低",
                    detail=f"路径 MTU 仅 {mtu_value}，低于 {policy.mtu.low}，大包传输会明显受限。",
                    advice=["检查 VPN / 隧道 / 中间设备的 MTU 设置"],
                    evidence=evidence,
                )
            )
        elif mtu_value < policy.mtu.pppoe:
            findings.append(
                Finding(
                    code=FindingCode.MTU_LOW,
                    severity=Severity.info,
                    title="路径 MTU 略低",
                    detail=f"路径 MTU 为 {mtu_value}，低于标准 1500。",
                    advice=["确认是否经过 VPN / 隧道；若网络正常可忽略"],
                    evidence=evidence,
                )
            )
        if not verified:
            findings.append(
                Finding(
                    code=FindingCode.MTU_UNVERIFIED,
                    severity=Severity.info,
                    title="MTU 未经确认",
                    detail="探测过程中出现超时等不确定信号，结果仅供参考。",
                    advice=["网络稳定后重新运行 status"],
                    evidence=evidence,
                )
            )

    metric = Metric(
        key="mtu",
        label="路径 MTU",
        value=float(mtu_value) if mtu_value is not None else None,
        unit="B",
        good=float(policy.mtu.standard),
        warn=float(policy.mtu.low),
        available=mtu_value is not None,
        note=None if mtu_value is not None else "探测失败",
    )
    return Section(id="mtu", title="MTU", metrics=[metric], findings=findings)


# ---------------------------------------------------------------------------
# 报告与命令入口
# ---------------------------------------------------------------------------


def _environment() -> dict[str, Any]:
    """运行环境快照：权限 / 解释器 / 系统 / 工作目录 / 系统访问层标识。"""
    return {
        "admin": platform.is_admin(),
        "python": sys_platform.python_version(),
        "platform": sys_platform.platform(),
        "cwd": os.getcwd(),
        "api": "iphlpapi",
    }


def _snapshot_gateway(gateway_ip: str | None, stat: PingStat | None) -> PingStat | None:
    """归因快照里的网关：没有默认路由时为 ``None``，探测失败时按不可达处理。"""
    if gateway_ip is None:
        return None
    if stat is not None:
        return stat
    return PingStat(target=gateway_ip, loss_pct=100.0, replies=0)


def _snapshot_wan(stat: PingStat | None) -> PingStat:
    """归因快照里的外网：探测失败时按不可达处理（``diagnose`` 要求非空）。"""
    if stat is not None:
        return stat
    return PingStat(target=WAN_HOST, loss_pct=100.0, replies=0)


def _merge_findings(
    diag_findings: Sequence[Finding],
    existing: Sequence[Finding] = (),
) -> list[Finding]:
    """按 ``code`` 去重合并顶层结论；归因结论（diagnose）优先保留。"""
    merged: list[Finding] = []
    seen: set[str] = set()
    for finding in diag_findings:
        if finding.code in seen:
            continue
        seen.add(finding.code)
        merged.append(finding)
    for finding in existing:
        if finding.code in seen:
            continue
        seen.add(finding.code)
        merged.append(finding)
    return merged


def build_status_report(
    run: Runner | None = None,
    *,
    dns_probe: Callable[[str, str], float | None] | None = None,
    http_probe: Callable[[str], float | None] | None = None,
    api: SystemApi | None = None,
    budget_seconds: float = 20.0,
) -> Report:
    """执行 status 的全部探测并返回 :class:`Report`。

    ``run`` 默认在**调用时**解析为 :func:`netopt.platform.run`（便于测试注入），
    ``api`` 默认 :class:`~netopt.system.live.LiveSystemApi`。``dns_probe`` /
    ``http_probe`` 仅用于兼容旧测试：给了就按「返回毫秒或 None」的旧语义
    测量，否则走 v2 测量层（``probes_dns`` / ``probes_http``）。

    总耗时受 ``budget_seconds``（默认 20 秒）约束；预算耗尽的探测会记
    ``timeout`` 并跳过后续测量，绝不静默吞掉失败。
    """
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    runner = run if run is not None else platform.run
    system = api if api is not None else LiveSystemApi()
    policy = Policy.default()
    ctx = ProbeContext.with_budget(budget_seconds)

    gateway_section, gateway_ip, gateway_stat = _gateway_section(system, runner, policy, ctx)
    wan_section, wan_stat = _wan_section(runner, policy, ctx)
    dns_section, dns_servers, dns_avg = _dns_section(system, policy, ctx, dns_probe)
    http_section, http_ttfb = _http_section(policy, ctx, http_probe)
    mtu_section = _mtu_section(runner, policy, ctx)

    snapshot = ConnectivitySnapshot(
        gateway=_snapshot_gateway(gateway_ip, gateway_stat),
        wan=_snapshot_wan(wan_stat),
        dns_avg_ms=dns_avg,
        dns_servers=dns_servers,
        http_ttfb_ms=http_ttfb,
    )
    diag_findings = diagnose(snapshot, policy)
    duration_ms = round((time.perf_counter() - started) * 1000)

    return Report(
        command="status",
        started_at=started_at,
        duration_ms=duration_ms,
        environment=_environment(),
        sections=[gateway_section, wan_section, dns_section, http_section, mtu_section],
        findings=_merge_findings(diag_findings),
        errors=list(ctx.errors),
    )
