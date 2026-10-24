# -*- coding: utf-8 -*-
"""``health`` 命令 —— 复用 status 探测，调用纯函数评分，产出 :class:`Report`。

设计取舍：

- **不重复探测**：健康评分需要的数据与 ``status`` 完全一致，直接复用
  :func:`netopt.commands.status.build_status_report`，避免两套阈值/两套探测。
- **评分是纯函数**：折算交给 :func:`netopt.analysis.health.evaluate`，本模块
  只做「Report → 输入模型」的适配与历史落盘。
- **历史写入失败不拖垮命令**：追加 JSONL 失败时产出一条
  ``SYSTEM_UNAVAILABLE``（warn），评分结果照常返回。
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netopt import history, paths
from netopt.analysis.health import evaluate
from netopt.commands.status import WAN_HOST, build_status_report
from netopt.domain import Finding, FindingCode, Policy, Report, Section, Severity
from netopt.models import MtuResult, PingStat
from netopt.platform import Runner
from netopt.system import SystemApi


def _metric_value(report: Report, section_id: str, key: str) -> tuple[float | None, bool]:
    """从某节的某个 metric 取 ``(value, available)``；找不到按不可用处理。"""
    for section in report.sections:
        if section.id != section_id:
            continue
        for metric in section.metrics:
            if metric.key == key:
                return metric.value, metric.available and metric.value is not None
    return None, False


def _ping_stat(report: Report, section_id: str, target: str) -> PingStat:
    """把「延迟 + 丢包」两项 metric 还原成 :class:`PingStat`。

    评分函数只读 ``avg_ms`` / ``loss_pct``；``replies`` 用于表达是否收到过回复。
    """
    latency, latency_ok = _metric_value(report, section_id, "latency")
    loss, loss_ok = _metric_value(report, section_id, "loss")
    avg = latency if latency_ok else None
    loss_pct = loss if loss_ok and loss is not None else (0.0 if avg is not None else 100.0)
    return PingStat(
        target=target,
        avg_ms=avg,
        loss_pct=loss_pct,
        replies=1 if avg is not None else 0,
    )


def _gateway_target(report: Report) -> str:
    """网关地址：优先取 status 网关节的 ``rows[0]["ip"]``。

    ``PingStat.target`` 只用于结论文案（如「网关 192.0.2.1 无 ping 回复」），
    拿不到地址时退回占位字符串，不影响评分。
    """
    for section in report.sections:
        if section.id != "gateway":
            continue
        for row in section.rows:
            value = row.get("ip")
            if isinstance(value, str) and value:
                return value
    return "gateway"


def _dns_servers(report: Report) -> list[str]:
    """从 DNS 节的 ``rows`` 还原服务器列表（status 用扁平键 ``servers``）。"""
    for section in report.sections:
        if section.id != "dns":
            continue
        for row in section.rows:
            raw = row.get("servers")
            if isinstance(raw, str) and raw.strip():
                return [item.strip() for item in raw.split(",") if item.strip()]
    return []


def _dns_latencies(report: Report) -> list[float | None]:
    """DNS 实测均值；不可用时返回空列表（评分会把 DNS 记 0 分）。"""
    value, available = _metric_value(report, "dns", "latency")
    return [value] if available and value is not None else []


def _dns_ipv6_only(report: Report) -> bool:
    """DNS 是否「只配置了 IPv6 服务器且未做 IPv4 实测」。

    status 对这种情形给出 ``DNS_IPV6_ONLY``（info），明确说明「不代表解析
    失败」；健康评分不能把它当成 ``DNS_FAIL``（critical），因此调用方会把
    DNS 从打分中排除。
    """
    for section in report.sections:
        if section.id != "dns":
            continue
        return any(
            finding.code == FindingCode.DNS_IPV6_ONLY for finding in section.findings
        ) and not _dns_latencies(report)
    return False


def _http_ttfb(report: Report) -> float | None:
    value, available = _metric_value(report, "http", "ttfb")
    return value if available else None


def _mtu_result(report: Report) -> MtuResult:
    """从 MTU 节还原 :class:`MtuResult`；``verified`` 由 ``MTU_UNVERIFIED`` 反推。"""
    value, available = _metric_value(report, "mtu", "mtu")
    verified = True
    for section in report.sections:
        if section.id != "mtu":
            continue
        if any(finding.code == FindingCode.MTU_UNVERIFIED for finding in section.findings):
            verified = False
    if not available or value is None:
        return MtuResult()
    mtu = int(value)
    return MtuResult(mtu=mtu, payload=mtu - 28, verified=verified)


def _merge_findings(primary: Sequence[Finding], secondary: Sequence[Finding]) -> list[Finding]:
    """按 ``code`` 去重；``primary``（评分结论）优先。"""
    merged: list[Finding] = []
    seen: set[str] = set()
    for finding in [*primary, *secondary]:
        if finding.code in seen:
            continue
        seen.add(finding.code)
        merged.append(finding)
    return merged


def _health_section(score_items: Sequence[dict[str, Any]], findings: Sequence[Finding]) -> Section:
    """把评分项渲染成 ``rows``（中文键，渲染层原样展示）。"""
    rows = [
        {
            "项目": str(item.get("label", "-")),
            "得分": f"{item.get('score', 0)}/{item.get('weight', 0)}",
            "说明": str(item.get("detail", "")),
        }
        for item in score_items
    ]
    return Section(id="health", title="健康评分", rows=rows, findings=list(findings))


def _write_history(
    path: Path, score_total: int, grade: str, items: Sequence[dict[str, Any]]
) -> None:
    """追加一条 health 历史；版本与字段保持稳定，供趋势读取。"""
    history.append(
        path,
        {
            "schema_version": 1,
            "kind": "health",
            "ts": datetime.now(UTC).isoformat(),
            "score": score_total,
            "grade": grade,
            "items": list(items),
        },
    )


def build_health_report(
    run: Runner | None = None,
    *,
    api: SystemApi | None = None,
    dns_probe: Callable[[str, str], float | None] | None = None,
    http_probe: Callable[[str], float | None] | None = None,
    budget_seconds: float = 20.0,
    history_path: Path | None = None,
) -> Report:
    """执行一次健康评估并返回 :class:`Report`。

    探测复用 ``status``；评分走 ``analysis.health.evaluate``；历史写 JSONL。
    """
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    policy = Policy.default()

    status = build_status_report(
        run=run,
        dns_probe=dns_probe,
        http_probe=http_probe,
        api=api,
        budget_seconds=budget_seconds,
    )

    dns_latencies = _dns_latencies(status)
    dns_servers = _dns_servers(status)
    dns_skipped = _dns_ipv6_only(status)
    if dns_skipped:
        # 只有 IPv6 DNS 时没有 IPv4 实测值：让 evaluate 跳过 DNS 打分，
        # 避免把「未测量」误判成 DNS_FAIL（status 已给出 DNS_IPV6_ONLY info）。
        dns_servers = []

    score, score_findings = evaluate(
        gateway=_ping_stat(status, "gateway", _gateway_target(status)),
        wan=_ping_stat(status, "wan", WAN_HOST),
        dns_latencies=dns_latencies,
        dns_servers=dns_servers,
        http_ttfb=_http_ttfb(status),
        mtu=_mtu_result(status),
        policy=policy,
    )
    if dns_skipped:
        # evaluate 对空服务器列表会补一条 DNS_NO_CONFIG（warn）；本例并非
        # 「没有配置」，用 status 的 DNS_IPV6_ONLY 说明已足够，丢弃它。
        score_findings = [
            finding for finding in score_findings if finding.code != FindingCode.DNS_NO_CONFIG
        ]

    findings = list(score_findings)
    target = history_path if history_path is not None else paths.history_path()
    try:
        _write_history(target, score.total, score.grade, score.items)
    except OSError as exc:
        findings.append(
            Finding(
                code=FindingCode.SYSTEM_UNAVAILABLE,
                severity=Severity.warn,
                title="健康历史写入失败",
                detail=f"无法写入 {target}：{type(exc).__name__}: {exc}",
                advice=["检查目录权限，或设置 NETOPT_HOME 指向可写目录"],
            )
        )

    duration_ms = round((time.perf_counter() - started) * 1000)
    return Report(
        command="health",
        started_at=started_at,
        duration_ms=duration_ms,
        environment={**status.environment, "history": str(target)},
        sections=[*status.sections, _health_section(score.items, findings)],
        findings=_merge_findings(findings, status.findings),
        errors=status.errors,
        score=score,
    )
