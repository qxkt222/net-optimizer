# -*- coding: utf-8 -*-
"""``http`` 命令 —— 多站点 HTTPS 首字节测量 → :class:`Report`。

固定测 4 个常用站点（百度 / 腾讯 / 哔哩哔哩 / 微软），每个站点一行，
记录 ``probes_http.measure`` 给出的 connect / TLS / TTFB / total 四段耗时
与状态码。节内指标取**最快站点**的 TTFB：它最能反映本机到公网的
最佳链路质量，单个站点慢（例如跨境站点）不应把整份报告判成故障。

失败语义：

- 单个站点失败不拖垮其他站点，失败原因写进该行 ``状态`` 与
  ``Report.errors``；
- 全部站点失败 → ``HTTP_FAIL``（critical）；部分失败 → ``HTTP_FAIL``（warn）；
- 最快 TTFB 超过 ``policy.http_ttfb.warn`` → ``HTTP_SLOW``。

本模块不打印、不执行系统命令；``measure`` 默认在调用时解析为
:func:`netopt.probes_http.measure`，测试可注入假函数。
"""

from __future__ import annotations

import os
import platform as sys_platform
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from netopt import platform, probes_http
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
from netopt.probes import ProbeContext

#: 固定测试站点：``(显示名, 域名)``。
SITES: Final[tuple[tuple[str, str], ...]] = (
    ("百度", "www.baidu.com"),
    ("腾讯", "www.qq.com"),
    ("哔哩哔哩", "www.bilibili.com"),
    ("微软", "www.microsoft.com"),
)

_VALID_ERROR_CODES: Final[frozenset[str]] = frozenset(code.value for code in ProbeErrorCode)
_RETRYABLE_CODES: Final[frozenset[str]] = frozenset(
    {ProbeErrorCode.TIMEOUT.value, ProbeErrorCode.NETWORK.value}
)


@dataclass(frozen=True)
class _SiteResult:
    """一个站点的测量结果；``ttfb`` 为 ``None`` 表示本次请求失败。"""

    name: str
    host: str
    status: int | None = None
    connect_ms: float | None = None
    tls_ms: float | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _as_float(value: object) -> float | None:
    """把任意返回值收敛成 ``float | None``；非法类型一律视为缺失。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _as_int(value: object) -> int | None:
    """把任意返回值收敛成 ``int | None``；``bool`` 与非法类型视为缺失。"""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


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


def _normalized_code(value: str | None) -> str:
    """只接受 :class:`ProbeErrorCode` 的取值，其余降级为 ``unavailable``。"""
    return value if value in _VALID_ERROR_CODES else ProbeErrorCode.UNAVAILABLE.value


# ---------------------------------------------------------------------------
# 单站点测量
# ---------------------------------------------------------------------------


def _measure_site(
    name: str,
    host: str,
    probe: Callable[..., Any],
    ctx: ProbeContext,
) -> _SiteResult:
    """测一个站点；任何异常都转成失败结果并写进上下文。"""
    source = f"http:{host}"
    if ctx.expired():
        _record_timeout(ctx, source, "总预算已耗尽，跳过探测")
        return _SiteResult(name, host, error="预算已耗尽")

    try:
        timing = probe(host)
    except Exception as exc:  # 探测边界必须把任何失败转成数据
        _record_unavailable(ctx, source, exc)
        return _SiteResult(name, host, error=f"{type(exc).__name__}: {exc}"[:200])

    if timing is None:
        message = "HTTP 测量没有返回结果"
        ctx.record_error(ProbeErrorCode.UNAVAILABLE.value, source, message)
        return _SiteResult(name, host, error=message)

    status = _as_int(getattr(timing, "status", None))
    connect_ms = _as_float(getattr(timing, "connect_ms", None))
    tls_ms = _as_float(getattr(timing, "tls_ms", None))
    total_ms = _as_float(getattr(timing, "total_ms", None))
    ttfb_ms = _as_float(getattr(timing, "ttfb_ms", None))
    if ttfb_ms is None:
        # TTFB 缺失时退回整次请求耗时（与 status 的口径一致）。
        ttfb_ms = total_ms
    error = _as_text(getattr(timing, "error", None))
    code = _as_text(getattr(timing, "error_code", None))

    if error is not None:
        normalized = _normalized_code(code)
        ctx.record_error(
            normalized,
            source,
            error,
            retryable=normalized in _RETRYABLE_CODES,
        )
    elif ttfb_ms is None:
        message = "HTTP 测量没有拿到任何耗时"
        ctx.record_error(ProbeErrorCode.UNAVAILABLE.value, source, message)
        error = message
    elif ctx.expired():
        # 结果仍可采用，但如实标注本次测量越过了总预算。
        _record_timeout(ctx, source, "探测超出总预算（结果仍采用）")

    return _SiteResult(
        name=name,
        host=host,
        status=status,
        connect_ms=connect_ms,
        tls_ms=tls_ms,
        ttfb_ms=ttfb_ms,
        total_ms=total_ms,
        error=error,
    )


# ---------------------------------------------------------------------------
# 结论与报告
# ---------------------------------------------------------------------------


def _findings(results: list[_SiteResult], policy: Policy, best: float | None) -> list[Finding]:
    """按 policy 产出 HTTP 结论：失败汇总 + 最快 TTFB 分档。"""
    findings: list[Finding] = []
    failed = [result for result in results if result.ttfb_ms is None]

    if failed and len(failed) == len(results):
        findings.append(
            Finding(
                code=FindingCode.HTTP_FAIL,
                severity=Severity.critical,
                title="HTTPS 连接全部失败",
                detail=f"{len(results)} 个站点均无法完成 HTTPS 请求（超时或连接被拒绝）。",
                advice=["确认外网连通后再测试", "检查防火墙 / 代理设置"],
                evidence=[
                    Evidence(source=f"http:{result.host}", detail=result.error) for result in failed
                ],
            )
        )
    elif failed:
        detail = "；".join(f"{result.name}（{result.error or '请求失败'}）" for result in failed)
        findings.append(
            Finding(
                code=FindingCode.HTTP_FAIL,
                severity=Severity.warn,
                title="部分站点访问失败",
                detail=f"{len(failed)}/{len(results)} 个站点无法完成 HTTPS 请求：{detail}。",
                advice=["稍后重试确认是否稳定复现", "检查代理 / 防火墙是否只拦截了部分域名"],
                evidence=[
                    Evidence(source=f"http:{result.host}", detail=result.error) for result in failed
                ],
            )
        )

    if best is not None and best > policy.http_ttfb.warn:
        fastest = min(
            (result for result in results if result.ttfb_ms is not None),
            key=lambda result: result.ttfb_ms if result.ttfb_ms is not None else float("inf"),
        )
        findings.append(
            Finding(
                code=FindingCode.HTTP_SLOW,
                severity=policy.http_ttfb.classify(best),
                title="HTTPS 首字节偏慢",
                detail=(
                    f"最快站点 {fastest.name} 的 TTFB 为 {best:.1f} ms，"
                    f"超过关注阈值 {policy.http_ttfb.warn:g} ms。"
                ),
                advice=["关闭占用带宽的后台程序", "尝试更换 DNS 或稍后重试"],
                evidence=[Evidence(source=f"http:{fastest.host}", detail=f"TTFB {best:.1f} ms")],
            )
        )
    return findings


def _rows(results: list[_SiteResult]) -> list[dict[str, Any]]:
    """每个站点一行：四段耗时 + 状态码 + 失败原因。"""
    return [
        {
            "站点": result.name,
            "域名": result.host,
            "状态码": result.status,
            "连接(ms)": result.connect_ms,
            "TLS(ms)": result.tls_ms,
            "TTFB(ms)": result.ttfb_ms,
            "总耗时(ms)": result.total_ms,
            "状态": "成功" if result.error is None else result.error,
        }
        for result in results
    ]


def _environment() -> dict[str, Any]:
    """运行环境快照：权限 / 解释器 / 系统 / 工作目录。"""
    return {
        "admin": platform.is_admin(),
        "python": sys_platform.python_version(),
        "platform": sys_platform.platform(),
        "cwd": os.getcwd(),
    }


def build_http_report(
    *,
    measure: Callable[..., Any] | None = None,
    budget_seconds: float = 20.0,
) -> Report:
    """测量 4 个站点的 HTTPS 耗时并返回 :class:`Report`。

    ``measure`` 缺省在调用时解析为 :func:`netopt.probes_http.measure`；
    总耗时受 ``budget_seconds``（默认 20 秒）约束，预算耗尽后跳过后续站点
    并记 ``timeout``。
    """
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    policy = Policy.default()
    ctx = ProbeContext.with_budget(budget_seconds)
    probe = measure if measure is not None else probes_http.measure

    results = [_measure_site(name, host, probe, ctx) for name, host in SITES]
    successes = [result.ttfb_ms for result in results if result.ttfb_ms is not None]
    best = min(successes) if successes else None

    metric = Metric(
        key="ttfb",
        label="最快首字节(TTFB)",
        value=best,
        unit="ms",
        good=policy.http_ttfb.good,
        warn=policy.http_ttfb.warn,
        available=best is not None,
        note=None if best is not None else "全部站点不可用",
    )
    section = Section(
        id="http",
        title="HTTP",
        metrics=[metric],
        rows=_rows(results),
        findings=_findings(results, policy, best),
    )

    duration_ms = round((time.perf_counter() - started) * 1000)
    return Report(
        command="http",
        started_at=started_at,
        duration_ms=duration_ms,
        environment=_environment(),
        sections=[section],
        findings=[],
        errors=list(ctx.errors),
    )


__all__ = ["SITES", "build_http_report"]
