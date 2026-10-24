# -*- coding: utf-8 -*-
"""``watch`` 命令 —— 常驻采样：status → 告警去抖 → 追加 ``metrics.jsonl``。

职责边界：

- **只做编排，不展示**：本模块不打印、不渲染；逐轮展示由 CLI 通过
  ``on_sample`` 回调完成，需要完整列表的调用方仍可保留 ``collect=True``。
- **告警去抖交给引擎**：同一 ``code`` 的冷却与累计由
  :class:`netopt.analysis.alerts.AlertEngine` 负责，本模块只把「顶层
  finding + 各节 finding」拼成一轮输入。
- **写盘失败不中断采样**：追加 JSONL 失败时把一条
  :class:`~netopt.domain.report.ProbeError`（``unavailable``）挂到本轮
  Report 的 ``errors`` 上，循环继续，下一轮仍会重试；失败绝不静默吞掉。
- **时间与等待可注入**：``now`` 只供告警冷却使用（单调时钟），``sleep``
  与 ``stop_event`` 也由调用方注入，因此测试不需要真实等待。
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netopt import history, paths
from netopt.analysis.alerts import Alert, AlertEngine
from netopt.domain import Finding, ProbeError, ProbeErrorCode, Report

#: 采样记录的默认文件名；与 ``history.jsonl`` 同目录（运行期 ``state`` 目录）。
_METRICS_FILENAME = "metrics.jsonl"


@dataclass(frozen=True)
class WatchSample:
    """一轮采样的结果：时间戳、完整 Report 与本轮应发出的告警。

    ``ts`` 是给 JSONL 与展示用的 ISO8601 时间（UTC）；``now`` 注入的
    单调时钟只影响告警冷却，不参与 ``ts`` 的生成。
    """

    ts: str
    report: Report
    alerts: list[Alert]


def _default_builder() -> Report:
    """默认采样构建器：在**调用时**解析 ``build_status_report``。

    延迟导入让测试可以 monkeypatch ``netopt.commands.status``，也避免
    模块导入期就把实现绑定死。
    """
    from netopt.commands.status import build_status_report

    return build_status_report()


def _all_findings(report: Report) -> list[Finding]:
    """顶层结论 + 各节结论，按报告中的顺序拼接（不做去重）。"""
    findings = list(report.findings)
    for section in report.sections:
        findings.extend(section.findings)
    return findings


def sample_once(
    *,
    builder: Callable[[], Report] | None = None,
    engine: AlertEngine | None = None,
    now: Callable[[], float] = time.monotonic,
) -> WatchSample:
    """执行一轮采样：构建 Report → 喂给告警引擎 → 打包成 :class:`WatchSample`。

    ``builder`` 为 ``None`` 时使用 :func:`_default_builder`（status）；
    ``engine`` 为 ``None`` 时按注入的 ``now`` 新建一个默认引擎 —— 单次
    调用没有跨轮状态，需要跨轮冷却时应由 :func:`run_watch` 复用同一个引擎。
    """
    build = builder if builder is not None else _default_builder
    report = build()
    active_engine = engine if engine is not None else AlertEngine(now=now)
    alerts = active_engine.feed(_all_findings(report))
    return WatchSample(ts=datetime.now(UTC).isoformat(), report=report, alerts=alerts)


def _stop_requested(stop_event: object | None) -> bool:
    """``stop_event`` 是否已请求停止。

    只要求对象提供 ``is_set()``（与 :class:`threading.Event` 的约定一致），
    因此测试可以用最轻量的替身，不必真的起线程。
    """
    if stop_event is None:
        return False
    is_set = getattr(stop_event, "is_set", None)
    if not callable(is_set):
        raise TypeError("stop_event 必须提供 is_set() 方法")
    return bool(is_set())


def _metrics_payload(report: Report) -> list[dict[str, Any]]:
    """把各节指标摊平成 JSONL 可读的列表。

    ``section`` + ``key`` 才是唯一键（``latency`` 在网关 / 外网 / DNS 各有一份），
    ``available=False`` 时 ``value`` 必须是 ``None``，不做任何填充。
    """
    payload: list[dict[str, Any]] = []
    for section in report.sections:
        for metric in section.metrics:
            payload.append(
                {
                    "section": section.id,
                    "key": metric.key,
                    "label": metric.label,
                    "value": metric.value,
                    "unit": metric.unit,
                    "available": metric.available,
                }
            )
    return payload


def _alerts_payload(alerts: list[Alert]) -> list[dict[str, Any]]:
    """把告警压成 JSONL 记录；``severity`` 用字符串值，便于趋势脚本过滤。"""
    return [
        {
            "code": alert.code,
            "severity": alert.severity.value,
            "title": alert.title,
            "detail": alert.detail,
            "count": alert.count,
            "active": alert.active,
        }
        for alert in alerts
    ]


def _record(sample: WatchSample) -> dict[str, Any]:
    """把一次采样压成 JSONL 记录；键名是趋势读取的稳定契约。

    ``score`` 只取百分制总分（没有评分时为 ``None``），完整评分明细仍在
    Report 里，不进指标历史，避免 JSONL 行过宽。
    """
    score = sample.report.score
    return {
        "kind": "watch",
        "ts": sample.ts,
        "score": score.total if score is not None else None,
        "metrics": _metrics_payload(sample.report),
        "alerts": _alerts_payload(sample.alerts),
    }


def _with_write_error(sample: WatchSample, target: Path, exc: OSError) -> WatchSample:
    """返回一个在 ``errors`` 里补了写盘失败的**新**样本。

    :class:`Report` 是 frozen 的，不能就地追加；用 ``model_copy`` 复制，
    失败码固定 ``unavailable``（写盘是本地 IO，不是网络问题）。
    """
    error = ProbeError(
        code=ProbeErrorCode.UNAVAILABLE.value,
        source="watch",
        message=f"无法写入 {target}：{type(exc).__name__}: {exc}",
        retryable=True,
    )
    report = sample.report.model_copy(
        update={"errors": [*sample.report.errors, error]},
    )
    return WatchSample(ts=sample.ts, report=report, alerts=sample.alerts)


def run_watch(
    *,
    builder: Callable[[], Report] | None = None,
    interval: float = 5.0,
    count: int | None = None,
    engine: AlertEngine | None = None,
    out_path: Path | None = None,
    sleep: Callable[[float], None] = time.sleep,
    stop_event: object | None = None,
    now: Callable[[], float] = time.monotonic,
    on_sample: Callable[[WatchSample], None] | None = None,
    collect: bool = True,
) -> list[WatchSample]:
    """循环采样并把每轮记录追加到 ``out_path``，返回本轮所有样本。

    - ``count=None`` 表示一直采样，直到 ``stop_event.is_set()`` 为真；
      ``count`` 为给定值时采满即停，最后一轮之后不再 ``sleep``。
    - ``out_path=None`` 时落到 ``paths.history_path()`` 同目录的
      ``metrics.jsonl``（即 ``state/metrics.jsonl``）。
    - ``engine=None`` 时用注入的 ``now`` 创建一个引擎并**跨轮复用**，
      这样默认规则（warn/critical、冷却 300 秒）才能生效。
    - 写盘失败只在对应样本的 ``report.errors`` 里留一条 ``unavailable``，
      不抛异常、不中断循环。
    - ``on_sample`` 在每轮**写盘之后**、等待下一轮之前调用，供 CLI 逐轮流式
      展示；回调异常不捕获，交由调用方处理。
    - ``collect=False`` 时**不累积**样本（常驻采样不会随轮数增长内存），
      返回值恒为空列表；轮数计数与 ``on_sample`` 不受影响。
    """
    if interval < 0:
        raise ValueError(f"interval 不能为负数: {interval!r}")
    if count is not None and count < 0:
        raise ValueError(f"count 不能为负数: {count!r}")

    target = out_path if out_path is not None else paths.history_path().parent / _METRICS_FILENAME
    active_engine = engine if engine is not None else AlertEngine(now=now)
    samples: list[WatchSample] = []
    rounds = 0

    while count is None or rounds < count:
        if _stop_requested(stop_event):
            break
        sample = sample_once(builder=builder, engine=active_engine, now=now)
        try:
            history.append(target, _record(sample))
        except OSError as exc:
            sample = _with_write_error(sample, target, exc)
        rounds += 1
        if collect:
            samples.append(sample)
        if on_sample is not None:
            on_sample(sample)
        if count is not None and rounds >= count:
            break
        if _stop_requested(stop_event):
            break
        sleep(interval)

    return samples
