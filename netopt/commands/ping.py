# -*- coding: utf-8 -*-
"""``ping`` 命令 —— 网关与目标主机 ping 探测 → :class:`Report`。

职责边界与 :mod:`netopt.commands.status` 一致：

- **只做编排与分档**：读默认路由走 :class:`~netopt.system.api.SystemApi`，
  测量走 :func:`netopt.probes.ping`，阈值一律取
  :meth:`netopt.domain.policy.Policy.default`；
- **不打印**：返回 :class:`~netopt.domain.report.Report`，由 ``netopt.render``
  统一消费；
- **失败不吞**：探测异常写进 :class:`~netopt.probes.ProbeContext.errors`
  并原样搬到 ``Report.errors``，对应指标标成 ``available=False``；
- **预算约束**：``budget_seconds`` 默认 20 秒，耗尽后不再启动新的 ping。

两节固定为 ``gateway``（默认路由下一跳）与 ``target``（默认
:data:`DEFAULT_TARGET`，可显式指定）。

结论码：网关复用 ``GATEWAY_*``；目标节复用 ``WAN_*`` ——
:class:`~netopt.domain.codes.FindingCode` 目前没有通用的 ``PING_*`` 码，
而目标通常是外网站点，语义与 status 的“外网”一节一致。后续若在
``codes.py`` 登记专用码，可在此处替换。
"""

from __future__ import annotations

import os
import platform as sys_platform
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol, TypeVar

from netopt import platform, probes
from netopt.domain import (
    Band,
    Evidence,
    Finding,
    FindingCode,
    Metric,
    Policy,
    ProbeErrorCode,
    Report,
    Route,
    Section,
    Severity,
)
from netopt.platform import Runner
from netopt.probes import ProbeContext
from netopt.system import LiveSystemApi, SystemApi

#: 未指定目标时与 v1 ``cmd_status`` 一致的默认外网站点。
DEFAULT_TARGET = "www.baidu.com"
#: 每台主机发送的 ICMP 请求数（SPEC §7.3：4 包）。
PING_COUNT = 4

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


def _guarded(
    ctx: ProbeContext,
    source: str,
    func: Callable[[], _T],
    default: _T | None = None,
) -> _T | None:
    """执行一次测量；失败记进上下文并返回 ``default``，绝不静默。

    预算已耗尽时不再启动新的测量，直接记一条 ``timeout``；结果越过预算
    但仍可用时如实标注，不丢弃测量值。
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
      :meth:`Band.classify`。
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


def _gateway_section(
    api: SystemApi,
    run: Runner,
    policy: Policy,
    ctx: ProbeContext,
) -> Section:
    """网关：默认路由的下一跳 + 延迟 / 丢包结论。"""
    route: Route | None = None
    read_ok = True
    try:
        route = probes.gateway_from_api(api)
    except Exception as exc:  # 读系统失败也要留下可解释的错误
        _record_unavailable(ctx, "iphlpapi", exc)
        read_ok = False

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

    stat = _guarded(
        ctx,
        f"ping:{gateway_ip}",
        lambda: probes.ping(gateway_ip, PING_COUNT, run=run),
        None,
    )
    return Section(
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


def _target_section(
    host: str,
    run: Runner,
    policy: Policy,
    ctx: ProbeContext,
) -> Section:
    """目标：ping 指定主机，结论码与 status 的“外网”一节同构。"""
    stat = _guarded(
        ctx,
        f"ping:{host}",
        lambda: probes.ping(host, PING_COUNT, run=run),
        None,
    )
    return Section(
        id="target",
        title="目标",
        metrics=_ping_metrics(stat, policy.wan, policy, note="目标 ping 探测失败"),
        rows=[{"target": host}],
        findings=_ping_findings(
            stat,
            band=policy.wan,
            policy=policy,
            codes=(
                FindingCode.WAN_UNREACHABLE,
                FindingCode.WAN_LOSS,
                FindingCode.WAN_LATENCY_HIGH,
            ),
            source=f"ping:{host}",
            label="目标",
        ),
    )


# ---------------------------------------------------------------------------
# 报告与命令入口
# ---------------------------------------------------------------------------


def _environment(target: str) -> dict[str, Any]:
    """运行环境快照：权限 / 解释器 / 系统 / 工作目录 / 系统访问层标识。"""
    return {
        "admin": platform.is_admin(),
        "python": sys_platform.python_version(),
        "platform": sys_platform.platform(),
        "cwd": os.getcwd(),
        "api": "iphlpapi",
        "target": target,
    }


def build_ping_report(
    target: str | None = None,
    *,
    run: Runner | None = None,
    api: SystemApi | None = None,
    budget_seconds: float = 20.0,
) -> Report:
    """执行网关与目标的 ping 探测并返回 :class:`Report`。

    ``target`` 缺省为 :data:`DEFAULT_TARGET`；``run`` 默认在**调用时**解析为
    :func:`netopt.platform.run`（便于测试注入），``api`` 默认
    :class:`~netopt.system.live.LiveSystemApi`。
    """
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    host = (target or "").strip() or DEFAULT_TARGET
    runner = run if run is not None else platform.run
    system = api if api is not None else LiveSystemApi()
    policy = Policy.default()
    ctx = ProbeContext.with_budget(budget_seconds)

    sections = [
        _gateway_section(system, runner, policy, ctx),
        _target_section(host, runner, policy, ctx),
    ]
    duration_ms = round((time.perf_counter() - started) * 1000)
    return Report(
        command="ping",
        started_at=started_at,
        duration_ms=duration_ms,
        environment=_environment(host),
        sections=sections,
        findings=[],
        errors=list(ctx.errors),
    )


__all__ = ["DEFAULT_TARGET", "PING_COUNT", "build_ping_report"]
