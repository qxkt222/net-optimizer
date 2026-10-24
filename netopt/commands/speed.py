# -*- coding: utf-8 -*-
"""``speed`` 命令 —— 多源下载 / 上传测速 → :class:`Report`。

固定 3 个下载源（Cloudflare / 阿里云镜像 / 清华镜像）与 1 个上传源
（Cloudflare），逐源调用 :mod:`netopt.probes_speed` 的多连接测速：

- 下载指标取**最快源**的聚合吞吐（多源取最大，代表线路可达的上限）；
- 每个源占一行，失败原因同时保留在行内 ``状态``、``Report.errors``
  与 ``SPEED_FAIL`` 结论中；
- 单个源失败不拖垮命令；全部下载源失败时额外产出一条 critical 结论。

``FindingCode`` 目前没有 ``SPEED_*`` 成员，而本任务的文件范围不允许修改
``netopt/domain/codes.py``，因此用模块常量 :data:`SPEED_FAIL` 固定取值，
避免在代码里散落字面量；后续登记专用码后可替换。

本模块不打印、不读写文件；``download`` / ``upload`` 默认在调用时解析为
:func:`netopt.probes_speed.download` / :func:`netopt.probes_speed.upload`，
测试可注入假函数。
"""

from __future__ import annotations

import os
import platform as sys_platform
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from netopt import platform, probes_speed
from netopt.domain import (
    Evidence,
    Finding,
    Metric,
    ProbeErrorCode,
    Report,
    Section,
    Severity,
)
from netopt.probes import ProbeContext

#: 下载源：与 v1 ``diag.SPEED_DOWNLOADS`` 保持一致，都是长期稳定的测速文件。
DOWNLOAD_SOURCES: Final[tuple[tuple[str, str], ...]] = (
    ("Cloudflare", "https://speed.cloudflare.com/__down?bytes=20000000"),
    ("阿里云镜像", "https://mirrors.aliyun.com/ubuntu/ls-lR.gz"),
    ("清华镜像", "https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ls-lR.gz"),
)

#: 上传源：Cloudflare 的 ``__up`` 端点接受任意 POST 负载。
#: 名称与下载源区分开，避免 ``ProbeError.source`` / 行状态串台。
UPLOAD_SOURCE: Final[tuple[str, str]] = (
    "Cloudflare 上传",
    "https://speed.cloudflare.com/__up",
)

#: 测速失败结论码（原因见模块 docstring）。
SPEED_FAIL: Final[str] = "SPEED_FAIL"

#: 单个源的最长测量时间；4 个源合计正好对上默认 60 秒预算。
PER_SOURCE_SECONDS: Final[float] = 15.0
#: 单条连接的请求超时上限。
PER_SOURCE_TIMEOUT: Final[float] = 10.0


@dataclass(frozen=True)
class _Entry:
    """一个测速源的结果；``mbps is None`` 表示该源整体失败。"""

    kind: str
    name: str
    mbps: float | None
    seconds: float | None
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


# ---------------------------------------------------------------------------
# 单源测速
# ---------------------------------------------------------------------------


def _run_source(
    kind: str,
    name: str,
    url: str,
    probe: Callable[..., Any],
    ctx: ProbeContext,
) -> _Entry:
    """执行一个源的测速；任何失败都转成带原因的条目，不抛异常。"""
    source = f"speed:{name}"
    if ctx.expired():
        _record_timeout(ctx, source, "总预算已耗尽，跳过测速")
        return _Entry(kind, name, None, None, "预算已耗尽")

    max_seconds = min(PER_SOURCE_SECONDS, ctx.remaining())
    timeout = min(PER_SOURCE_TIMEOUT, max_seconds)
    try:
        result = probe(name, url, max_seconds=max_seconds, timeout=timeout)
    except Exception as exc:  # 探测边界必须把任何失败转成数据
        _record_unavailable(ctx, source, exc)
        return _Entry(kind, name, None, None, f"{type(exc).__name__}: {exc}"[:200])

    if result is None:
        message = "测速没有返回结果"
        ctx.record_error(ProbeErrorCode.UNAVAILABLE.value, source, message)
        return _Entry(kind, name, None, None, message)

    mbps = _as_float(getattr(result, "mbps", None))
    seconds = _as_float(getattr(result, "seconds", None))
    error = _as_text(getattr(result, "error", None))
    if mbps is None and error is None:
        error = "没有测到有效速率"
    if error is not None and not _has_error(ctx, source):
        # 单条连接失败时 probes_speed 仍可能返回聚合速率：速率照用，
        # 但失败原因必须保留下来。
        ctx.record_error(
            ProbeErrorCode.UNAVAILABLE.value,
            source,
            error,
            retryable=True,
        )
    elif mbps is not None and ctx.expired() and not _has_error(ctx, source):
        _record_timeout(ctx, source, "探测超出总预算（结果仍采用）")

    return _Entry(kind, name, mbps, seconds, error)


# ---------------------------------------------------------------------------
# 结论与报告
# ---------------------------------------------------------------------------


def _findings(entries: list[_Entry]) -> list[Finding]:
    """每个失败源一条 warn；全部下载源失败时再加一条 critical。"""
    findings: list[Finding] = []
    for entry in entries:
        if entry.error is None:
            continue
        succeeded = entry.mbps is not None
        findings.append(
            Finding(
                code=SPEED_FAIL,
                severity=Severity.warn,
                title=f"{entry.name} 测速{'部分失败' if succeeded else '失败'}",
                detail=f"{entry.kind}源 {entry.name}：{entry.error}",
                advice=["稍后重试", "检查网络连接，或更换测速源"],
                evidence=[Evidence(source=f"speed:{entry.name}", detail=entry.error)],
            )
        )

    downloads = [entry for entry in entries if entry.kind == "下载"]
    if downloads and all(entry.mbps is None for entry in downloads):
        findings.append(
            Finding(
                code=SPEED_FAIL,
                severity=Severity.critical,
                title="下载测速全部失败",
                detail=f"{len(downloads)} 个下载源都没有测到有效速率，外网可能不可达或被限速。",
                advice=["确认外网连通后再测试", "检查防火墙 / 代理 / 运营商限速设置"],
                evidence=[Evidence(source="speed:download", detail="全部下载源失败")],
            )
        )
    return findings


def _rows(entries: list[_Entry]) -> list[dict[str, Any]]:
    """每个源一行：类型 / 源名 / 速率 / 耗时 / 失败原因。"""
    return [
        {
            "类型": entry.kind,
            "源": entry.name,
            "速率(Mbps)": entry.mbps,
            "耗时(s)": entry.seconds,
            "状态": "成功" if entry.error is None else entry.error,
        }
        for entry in entries
    ]


def _metric(key: str, label: str, value: float | None, note: str) -> Metric:
    """测速指标：Policy 没有速率档位，因此不填 ``good`` / ``warn``。"""
    return Metric(
        key=key,
        label=label,
        value=value,
        unit="Mbps",
        available=value is not None,
        note=None if value is not None else note,
    )


def _environment() -> dict[str, Any]:
    """运行环境快照：权限 / 解释器 / 系统 / 工作目录。"""
    return {
        "admin": platform.is_admin(),
        "python": sys_platform.python_version(),
        "platform": sys_platform.platform(),
        "cwd": os.getcwd(),
    }


def build_speed_report(
    *,
    download: Callable[..., Any] | None = None,
    upload: Callable[..., Any] | None = None,
    budget_seconds: float = 60.0,
) -> Report:
    """依次测试 3 个下载源与 1 个上传源并返回 :class:`Report`。

    ``download`` / ``upload`` 缺省在调用时解析为
    :func:`netopt.probes_speed.download` / :func:`netopt.probes_speed.upload`。
    总预算默认 60 秒，单源最长 15 秒；预算耗尽后跳过剩余源并记 ``timeout``。
    """
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    ctx = ProbeContext.with_budget(budget_seconds)
    download_probe = download if download is not None else probes_speed.download
    upload_probe = upload if upload is not None else probes_speed.upload

    entries: list[_Entry] = [
        _run_source("下载", name, url, download_probe, ctx) for name, url in DOWNLOAD_SOURCES
    ]
    entries.append(_run_source("上传", *UPLOAD_SOURCE, upload_probe, ctx))

    downloads = [entry for entry in entries if entry.kind == "下载"]
    download_best = max(
        (entry.mbps for entry in downloads if entry.mbps is not None),
        default=None,
    )
    upload_entry = entries[-1]
    metrics = [
        _metric("download", "下载", download_best, "全部下载源失败"),
        _metric("upload", "上传", upload_entry.mbps, "上传源失败"),
    ]
    section = Section(
        id="speed",
        title="测速",
        metrics=metrics,
        rows=_rows(entries),
        findings=_findings(entries),
    )

    duration_ms = round((time.perf_counter() - started) * 1000)
    return Report(
        command="speed",
        started_at=started_at,
        duration_ms=duration_ms,
        environment=_environment(),
        sections=[section],
        findings=[],
        errors=list(ctx.errors),
    )


__all__ = [
    "DOWNLOAD_SOURCES",
    "PER_SOURCE_SECONDS",
    "PER_SOURCE_TIMEOUT",
    "SPEED_FAIL",
    "UPLOAD_SOURCE",
    "build_speed_report",
]
