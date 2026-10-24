# -*- coding: utf-8 -*-
"""``dns`` 命令 —— 公共 DNS 基准测试 + 当前系统 DNS → :class:`Report`。

探测口径（SPEC §7.3）：

- 7 台常用公共 DNS（阿里 / 腾讯 / 114 / Google / Cloudflare / 百度 / OpenDNS）
  加上当前系统配置的 DNS 服务器；
- 每台查询 :data:`DNS_ATTEMPTS` 次取平均，失败保留最后一次失败原因；
- 结果按耗时升序放进 ``Section.rows``，失败项排在最后；
- 阈值取 :meth:`netopt.domain.policy.Policy.default` 的 ``dns`` 档位。

实现约束：

- 不打印、不执行系统命令（系统 DNS 走 :class:`~netopt.system.api.SystemApi`）。
  为了兼容 v1 的注入习惯，仍接受 ``run``：只有在没有给 ``api`` 时才用
  :func:`netopt.probes.dns_config` 经 ``netsh`` 读取配置；
- ``benchmark`` 默认在**调用时**解析为 :func:`netopt.probes_dns.benchmark`，
  测试可注入假函数；
- 任何探测失败都写进 ``Report.errors``，对应指标标成 ``available=False``。
"""

from __future__ import annotations

import os
import platform as sys_platform
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from netopt import platform, probes, probes_dns
from netopt.domain import (
    Evidence,
    Finding,
    FindingCode,
    Metric,
    Policy,
    ProbeErrorCode,
    Report,
    Section,
    Severity,
)
from netopt.platform import Runner
from netopt.probes import ProbeContext
from netopt.system import LiveSystemApi, SystemApi

#: 7 台公共 DNS：``(显示名, 地址)``。地址都是各家的主服务地址。
PUBLIC_DNS: Final[tuple[tuple[str, str], ...]] = (
    ("阿里 DNS", "223.5.5.5"),
    ("腾讯 DNS", "119.29.29.29"),
    ("114 DNS", "114.114.114.114"),
    ("Google DNS", "8.8.8.8"),
    ("Cloudflare DNS", "1.1.1.1"),
    ("百度 DNS", "180.76.76.76"),
    ("OpenDNS", "208.67.222.222"),
)

#: 基准查询使用的主机名：与 status 的外网目标一致，便于横向比较。
DNS_TEST_HOST = "www.baidu.com"
#: 每台服务器的查询次数（取平均，减少单次抖动）。
DNS_ATTEMPTS = 3

_VALID_ERROR_CODES: Final[frozenset[str]] = frozenset(code.value for code in ProbeErrorCode)
_RETRYABLE_CODES: Final[frozenset[str]] = frozenset(
    {ProbeErrorCode.TIMEOUT.value, ProbeErrorCode.NETWORK.value}
)


@dataclass(frozen=True)
class _Entry:
    """一台 DNS 服务器的基准测试结果（供排序与出结论使用）。"""

    name: str
    server: str
    source: str
    elapsed: float | None
    error: str | None


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _as_float(value: object) -> float | None:
    """把任意返回值收敛成 ``float | None``；非法类型一律视为缺失。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _as_text(value: object) -> str | None:
    """把任意返回值收敛成不超过 200 字的文本；空值返回 ``None``。"""
    if value is None:
        return None
    text = str(value).strip()
    return text[:200] if text else None


def _record_unavailable(ctx: ProbeContext, source: str, exc: BaseException) -> None:
    """把异常翻译成可解释的错误并记进上下文。"""
    message = f"{type(exc).__name__}: {exc}"[:200]
    ctx.record_error(ProbeErrorCode.UNAVAILABLE.value, source, message)


def _record_timeout(ctx: ProbeContext, source: str, message: str) -> None:
    """记录一条超时/无响应；这类失败通常换个时机重试有意义。"""
    ctx.record_error(ProbeErrorCode.TIMEOUT.value, source, message, retryable=True)


def _has_error(ctx: ProbeContext, source: str) -> bool:
    """上下文里是否已经有某个来源的错误（避免重复记录）。"""
    return any(error.source == source for error in ctx.errors)


def _normalized_code(value: str | None) -> str:
    """只接受 :class:`ProbeErrorCode` 的取值，其余降级为 ``unavailable``。"""
    return value if value in _VALID_ERROR_CODES else ProbeErrorCode.UNAVAILABLE.value


# ---------------------------------------------------------------------------
# 系统 DNS 读取
# ---------------------------------------------------------------------------


def _read_configs(api: SystemApi | None, run: Runner | None) -> tuple[list[Any], str]:
    """读取当前系统 DNS 配置，返回 ``(配置列表, 读取途径)``。

    优先 ``SystemApi``（v2 读路径）；只有在没有 ``api`` 且显式给了 ``run``
    时才回退 v1 的 ``netsh`` 解析，避免默认路径执行子进程。
    """
    if api is not None:
        return list(probes.dns_from_api(api)), "iphlpapi"
    if run is not None:
        return list(probes.dns_config(run)), "netsh"
    return list(probes.dns_from_api(LiveSystemApi())), "iphlpapi"


def _system_entries(configs: list[Any]) -> list[tuple[str, str]]:
    """把各接口配置展开成 ``(显示名, 地址)``，按地址去重并保持原顺序。

    同时兼容 :class:`~netopt.domain.models.InterfaceDns`（``interface_name``）
    与 v1 :class:`~netopt.models.DnsConfig`（``interface``）。
    """
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for config in configs:
        interface = (
            _as_text(getattr(config, "interface_name", None))
            or _as_text(getattr(config, "interface", None))
            or "系统 DNS"
        )
        label = "系统 DNS" if interface == "系统 DNS" else f"系统 DNS（{interface}）"
        for raw in getattr(config, "servers", []) or []:
            server = _as_text(raw)
            if server is None or server in seen:
                continue
            seen.add(server)
            entries.append((label, server))
    return entries


def _requested_servers(system_entries: list[tuple[str, str]]) -> list[tuple[str, str, str]]:
    """合并公共 DNS 与系统 DNS：``(显示名, 地址, 来源)``，地址去重。"""
    requested: list[tuple[str, str, str]] = [(name, server, "公共") for name, server in PUBLIC_DNS]
    seen = {server for _, server, _ in requested}
    for name, server in system_entries:
        if server in seen:
            continue
        seen.add(server)
        requested.append((name, server, "系统"))
    return requested


# ---------------------------------------------------------------------------
# 基准测试编排
# ---------------------------------------------------------------------------


def _record_result_error(
    ctx: ProbeContext,
    server: str,
    code: str | None,
    message: str | None,
) -> None:
    """把一条失败结果落到 ``ProbeContext``；已有同源错误时不重复。"""
    source = f"dns:{server}"
    if _has_error(ctx, source):
        return
    normalized = _normalized_code(code)
    ctx.record_error(
        normalized,
        source,
        message or "无响应",
        retryable=normalized in _RETRYABLE_CODES,
    )


def _benchmark(
    requested: list[tuple[str, str, str]],
    probe: Callable[..., list[Any]],
    ctx: ProbeContext,
) -> tuple[list[_Entry], bool]:
    """跑一轮基准测试，返回 ``(条目列表, benchmark 是否正常返回)``。

    ``benchmark`` 抛异常、预算耗尽或返回空列表时，调用方仍能拿到每台
    服务器的占位条目，不会因为一次失败丢掉整张表。
    """
    servers = [server for _, server, _ in requested]
    results: list[Any] = []
    ok = True
    if ctx.expired():
        _record_timeout(ctx, "dns", "总预算已耗尽，跳过 DNS 基准测试")
        ok = False
    else:
        try:
            results = list(probe(servers, DNS_TEST_HOST, attempts=DNS_ATTEMPTS, ctx=ctx))
        except Exception as exc:  # 探测边界：基准测试本身失败也要留下错误
            _record_unavailable(ctx, "dns", exc)
            ok = False
        else:
            if ctx.expired():
                _record_timeout(ctx, "dns", "探测超出总预算（结果仍采用）")

    by_server: dict[str, Any] = {}
    for result in results:
        server = _as_text(getattr(result, "server", None))
        if server is not None:
            by_server[server] = result

    entries: list[_Entry] = []
    for name, server, source in requested:
        result = by_server.get(server)
        if result is None:
            message = "基准测试没有返回该服务器的结果"
            if ok:
                _record_result_error(ctx, server, ProbeErrorCode.UNAVAILABLE.value, message)
            else:
                message = "基准测试未完成"
            entries.append(_Entry(name, server, source, None, message))
            continue

        elapsed = _as_float(getattr(result, "elapsed_ms", None))
        if elapsed is not None:
            entries.append(_Entry(name, server, source, elapsed, None))
            continue

        message = _as_text(getattr(result, "error", None)) or "无响应"
        code = _as_text(getattr(result, "error_code", None))
        _record_result_error(ctx, server, code, message)
        entries.append(_Entry(name, server, source, None, message))
    return entries, ok


# ---------------------------------------------------------------------------
# 结论与报告
# ---------------------------------------------------------------------------


def _findings(
    entries: list[_Entry],
    policy: Policy,
    *,
    has_system_config: bool,
    read_ok: bool,
    best: float | None,
) -> list[Finding]:
    """按 policy 产出 DNS 选型结论。

    - 没有任何成功项 → ``DNS_FAIL``（critical）；
    - 系统 DNS 全部失败但公共 DNS 可用 → ``DNS_FAIL``（warn，建议更换）；
    - 没有配置系统 DNS → ``DNS_NO_CONFIG``（warn）；
    - 最快解析耗时超过 ``policy.dns.warn`` → ``DNS_SLOW``。
    """
    findings: list[Finding] = []
    successes = [entry for entry in entries if entry.elapsed is not None]
    system_entries = [entry for entry in entries if entry.source == "系统"]

    if not successes:
        findings.append(
            Finding(
                code=FindingCode.DNS_FAIL,
                severity=Severity.critical,
                title="DNS 解析全部失败",
                detail=f"向 {len(entries)} 台 DNS 服务器查询 {DNS_TEST_HOST} 均无响应。",
                advice=[
                    "确认外网连通后再测试",
                    "检查防火墙 / 安全软件是否拦截 UDP 53 端口",
                ],
                evidence=[Evidence(source="dns", detail="全部服务器无响应")],
            )
        )
    elif system_entries and all(entry.elapsed is None for entry in system_entries):
        failed = ", ".join(entry.server for entry in system_entries)
        findings.append(
            Finding(
                code=FindingCode.DNS_FAIL,
                severity=Severity.warn,
                title="当前系统 DNS 不可用",
                detail=f"系统配置的 DNS（{failed}）均无响应，公共 DNS 可以正常解析。",
                advice=["运行 'netopt fix dns' 更换为响应正常的公共 DNS"],
                evidence=[Evidence(source="dns_config", detail=failed)],
            )
        )

    if read_ok and not has_system_config:
        findings.append(
            Finding(
                code=FindingCode.DNS_NO_CONFIG,
                severity=Severity.warn,
                title="未配置 DNS 服务器",
                detail="所有接口都没有解析器地址，域名解析只能依赖本次基准测试的公共 DNS。",
                advice=["运行 'netopt fix dns' 写入公共 DNS"],
                evidence=[Evidence(source="dns_config")],
            )
        )

    if best is not None and best > policy.dns.warn:
        findings.append(
            Finding(
                code=FindingCode.DNS_SLOW,
                severity=policy.dns.classify(best),
                title="DNS 解析偏慢",
                detail=f"最快解析耗时 {best:.1f} ms，超过关注阈值 {policy.dns.warn:g} ms。",
                advice=["更换更近的公共 DNS（如 223.5.5.5）", "检查路由器 DNS 转发设置"],
                evidence=[Evidence(source="dns", detail=f"最快 {best:.1f} ms")],
            )
        )
    return findings


def _rows(entries: list[_Entry]) -> list[dict[str, Any]]:
    """按耗时升序生成 rows；失败项排在最后，保留失败原因。"""
    ordered = sorted(
        entries,
        key=lambda entry: (
            entry.elapsed is None,
            entry.elapsed if entry.elapsed is not None else 0.0,
            entry.server,
        ),
    )
    return [
        {
            "名称": entry.name,
            "地址": entry.server,
            "耗时(ms)": entry.elapsed,
            "状态": "成功" if entry.elapsed is not None else (entry.error or "无响应"),
            "来源": entry.source,
        }
        for entry in ordered
    ]


def _environment(read_source: str) -> dict[str, Any]:
    """运行环境快照：权限 / 解释器 / 系统 / 工作目录 / 系统 DNS 读取途径。"""
    return {
        "admin": platform.is_admin(),
        "python": sys_platform.python_version(),
        "platform": sys_platform.platform(),
        "cwd": os.getcwd(),
        "api": read_source,
        "test_host": DNS_TEST_HOST,
    }


def build_dns_report(
    *,
    run: Runner | None = None,
    api: SystemApi | None = None,
    benchmark: Callable[..., list[Any]] | None = None,
    budget_seconds: float = 30.0,
) -> Report:
    """对公共 DNS 与系统 DNS 做基准测试并返回 :class:`Report`。

    ``api`` 缺省时使用 :class:`~netopt.system.live.LiveSystemApi` 读取系统
    DNS；显式给了 ``run`` 且未给 ``api`` 时走 v1 的 ``netsh`` 解析。
    ``benchmark`` 缺省在调用时解析为 :func:`netopt.probes_dns.benchmark`。
    """
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    policy = Policy.default()
    ctx = ProbeContext.with_budget(budget_seconds)

    configs: list[Any] = []
    read_ok = True
    read_source = "iphlpapi" if api is not None or run is None else "netsh"
    try:
        configs, read_source = _read_configs(api, run)
    except Exception as exc:  # 读配置失败不影响公共 DNS 基准测试
        _record_unavailable(ctx, read_source, exc)
        read_ok = False

    system_entries = _system_entries(configs)
    requested = _requested_servers(system_entries)
    probe = benchmark if benchmark is not None else probes_dns.benchmark
    entries, _ok = _benchmark(requested, probe, ctx)

    successes = [entry.elapsed for entry in entries if entry.elapsed is not None]
    best = min(successes) if successes else None
    findings = _findings(
        entries,
        policy,
        has_system_config=bool(system_entries),
        read_ok=read_ok,
        best=best,
    )

    metric = Metric(
        key="latency",
        label="最快解析耗时",
        value=best,
        unit="ms",
        good=policy.dns.good,
        warn=policy.dns.warn,
        available=best is not None,
        note=None if best is not None else "全部服务器无响应",
    )
    section = Section(
        id="dns",
        title="DNS 服务器",
        metrics=[metric],
        rows=_rows(entries),
        findings=findings,
    )

    duration_ms = round((time.perf_counter() - started) * 1000)
    return Report(
        command="dns",
        started_at=started_at,
        duration_ms=duration_ms,
        environment=_environment(read_source),
        sections=[section],
        findings=[],
        errors=list(ctx.errors),
    )


__all__ = [
    "DNS_ATTEMPTS",
    "DNS_TEST_HOST",
    "PUBLIC_DNS",
    "build_dns_report",
]
