# -*- coding: utf-8 -*-
"""``wifi`` 命令 —— WLAN 状态 + 周边扫描 → :class:`Report`。

职责边界：

- **只读系统**：当前连接取 :meth:`SystemApi.wifi`，周边网络取
  :meth:`SystemApi.wifi_scan`；本模块不执行 ``netsh``、不碰 ctypes。
- **不打印**：结果全部交给 ``netopt.render``；CLI / GUI 复用同一份数据。
- **失败不吞**：读状态 / 扫描抛异常时写 ``ProbeError`` 并产出
  ``SYSTEM_UNAVAILABLE``；位置权限不足时扫描实现返回 ``available=False``，
  这里翻译成 ``WIFI_LOCATION_DENIED`` 并把原始原因写进 detail。
- **信道按频段统计**：2.4GHz 与 5GHz 的同号信道互不干扰，``rows`` 以频段为键
  （如 ``{"2.4GHz": "信道6:2  信道11:1"}``），未提供频段时按信道号推断。

结论码全部取自 :class:`netopt.domain.codes.FindingCode` 的既有成员：
``WIFI_DISCONNECTED`` / ``WIFI_SIGNAL_WEAK`` / ``WIFI_LOCATION_DENIED``。
"""

from __future__ import annotations

import os
import platform as sys_platform
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from netopt import platform
from netopt.domain import (
    Evidence,
    Finding,
    FindingCode,
    ProbeError,
    ProbeErrorCode,
    Report,
    Section,
    Severity,
    WifiNetwork,
    WifiScan,
    WifiState,
)
from netopt.system import LiveSystemApi, SystemApi

__all__ = ["WEAK_SIGNAL_PCT", "build_wifi_report"]

#: 信号强度低于该百分比视为弱信号（任务书冻结的阈值）。
WEAK_SIGNAL_PCT = 40

#: 频段的展示顺序；未知频段排在后面按名称排序。
_BAND_ORDER = ("2.4GHz", "5GHz", "6GHz")


def _environment() -> dict[str, Any]:
    """运行环境快照：权限 / 解释器 / 系统 / 工作目录 / 系统访问层标识。"""
    return {
        "admin": platform.is_admin(),
        "python": sys_platform.python_version(),
        "platform": sys_platform.platform(),
        "cwd": os.getcwd(),
        "api": "wlanapi",
    }


# ---------------------------------------------------------------------------
# 当前连接
# ---------------------------------------------------------------------------


def _band_from_channel(channel: int) -> str | None:
    """没有频段信息时按信道号推断；范围与 ``system.wlanapi`` 保持一致。"""
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 177:
        return "5GHz"
    if 178 <= channel <= 233:
        return "6GHz"
    return None


def _state_rows(state: WifiState) -> list[dict[str, Any]]:
    """已连接时输出一行当前连接信息；未连接不造数据。"""
    if not state.connected:
        return []
    row: dict[str, Any] = {}
    if state.ssid is not None:
        row["ssid"] = state.ssid
    if state.channel is not None:
        row["channel"] = state.channel
    band = (
        state.band
        if state.band is not None
        else (_band_from_channel(state.channel) if state.channel is not None else None)
    )
    if band is not None:
        row["band"] = band
    if state.signal_pct is not None:
        row["signal"] = f"{state.signal_pct}%"
    return [row] if row else []


def _state_findings(state: WifiState) -> list[Finding]:
    """按连接状态与信号强度产出结论；正常连接不刷 info。"""
    if not state.connected:
        detail = "当前没有连接任何 WiFi 网络。"
        if state.state:
            detail = f"当前没有连接任何 WiFi 网络（状态：{state.state}）。"
        return [
            Finding(
                code=FindingCode.WIFI_DISCONNECTED,
                severity=Severity.info,
                title="未连接 WiFi",
                detail=detail,
                advice=[
                    "需要无线时请在系统设置中连接 WiFi",
                    "使用有线连接时可忽略此提示",
                ],
                evidence=[Evidence(source="wlanapi", detail=state.interface)],
            )
        ]
    if state.signal_pct is not None and state.signal_pct < WEAK_SIGNAL_PCT:
        return [
            Finding(
                code=FindingCode.WIFI_SIGNAL_WEAK,
                severity=Severity.warn,
                title="WiFi 信号偏弱",
                detail=(
                    f"当前信号强度 {state.signal_pct}%，低于 {WEAK_SIGNAL_PCT}%，"
                    "可能出现掉线或速率下降。"
                ),
                advice=[
                    "靠近路由器，或减少墙体 / 金属物遮挡",
                    "优先使用 5GHz 频段或改用有线连接",
                ],
                evidence=[
                    Evidence(
                        source="wlanapi",
                        detail=f"SSID {state.ssid or '-'}，信号 {state.signal_pct}%",
                    )
                ],
            )
        ]
    return []


# ---------------------------------------------------------------------------
# 周边扫描与信道占用
# ---------------------------------------------------------------------------


def _channel_counts(networks: Sequence[WifiNetwork]) -> dict[str, dict[int, int]]:
    """按频段统计每个信道上的 BSS 数量；每个网络计 1 次。

    没有信道或无法判断频段的条目跳过，不猜测、不造数据。
    """
    by_band: dict[str, dict[int, int]] = {}
    for network in networks:
        channel = network.channel
        if channel is None:
            continue
        band = network.band if network.band is not None else _band_from_channel(channel)
        if band is None:
            continue
        per_channel = by_band.setdefault(band, {})
        per_channel[channel] = per_channel.get(channel, 0) + 1
    return by_band


def _band_sort_key(band: str) -> tuple[int, str]:
    """已知频段按固定顺序，未知频段排在后面按名称排序。"""
    if band in _BAND_ORDER:
        return (_BAND_ORDER.index(band), band)
    return (len(_BAND_ORDER), band)


def _occupancy_rows(counts: Mapping[str, Mapping[int, int]]) -> list[dict[str, Any]]:
    """把频段 → 信道计数转成 ``rows``：每个频段一行，信道按占用降序。"""
    rows: list[dict[str, Any]] = []
    for band in sorted(counts, key=_band_sort_key):
        per_channel = counts[band]
        if not per_channel:
            continue
        ranked = sorted(per_channel.items(), key=lambda item: (-item[1], item[0]))
        detail = "  ".join(f"信道{channel}:{count}" for channel, count in ranked)
        rows.append({band: detail})
    return rows


def _scan_findings(scan: WifiScan) -> list[Finding]:
    """扫描不可用时的结论：统一按位置权限受限表达，detail 保留原始原因。"""
    if scan.available:
        return []
    reason = scan.error or "扫描接口未提供原因"
    return [
        Finding(
            code=FindingCode.WIFI_LOCATION_DENIED,
            severity=Severity.warn,
            title="无法扫描周边 WiFi",
            detail=f"周边网络扫描不可用：{reason}",
            advice=[
                "在「设置 → 隐私和安全性 → 位置」中开启位置服务，并允许桌面应用访问位置",
                "确认无线网卡驱动与 WLAN 服务正常后重试",
            ],
            evidence=[Evidence(source="wlanapi", detail=reason)],
        )
    ]


# ---------------------------------------------------------------------------
# 报告入口
# ---------------------------------------------------------------------------


def _read_state(system: SystemApi) -> tuple[WifiState | None, ProbeError | None, Finding | None]:
    """读当前连接；失败时返回可解释的错误与结论，不让异常穿透。"""
    try:
        return system.wifi(), None, None
    except Exception as exc:  # 探测边界：任何系统读取失败都转成数据
        message = f"{type(exc).__name__}: {exc}"[:200]
        error = ProbeError(
            code=ProbeErrorCode.UNAVAILABLE,
            source="wlanapi",
            message=message,
        )
        finding = Finding(
            code=FindingCode.SYSTEM_UNAVAILABLE,
            severity=Severity.warn,
            title="无法读取 WiFi 状态",
            detail=f"读取 WLAN 状态失败：{message}",
            advice=["确认无线网卡驱动与 WLAN AutoConfig 服务正常", "有线环境下可忽略"],
            evidence=[Evidence(source="wlanapi")],
        )
        return None, error, finding


def _read_scan(system: SystemApi) -> tuple[WifiScan | None, ProbeError | None, Finding | None]:
    """读周边扫描；失败时同样转成错误与结论。"""
    try:
        return system.wifi_scan(), None, None
    except Exception as exc:  # 探测边界：任何系统读取失败都转成数据
        message = f"{type(exc).__name__}: {exc}"[:200]
        error = ProbeError(
            code=ProbeErrorCode.UNAVAILABLE,
            source="wlanapi",
            message=message,
        )
        finding = Finding(
            code=FindingCode.SYSTEM_UNAVAILABLE,
            severity=Severity.warn,
            title="无法扫描周边 WiFi",
            detail=f"周边网络扫描失败：{message}",
            advice=["确认无线网卡驱动与 WLAN AutoConfig 服务正常"],
            evidence=[Evidence(source="wlanapi")],
        )
        return None, error, finding


def build_wifi_report(*, api: SystemApi | None = None) -> Report:
    """读取 WiFi 状态与周边扫描并返回 :class:`Report`。

    ``api`` 默认在**调用时**解析为 :class:`~netopt.system.live.LiveSystemApi`
    （便于测试注入 ``FakeSystemApi``）：

    - 未连接 → ``WIFI_DISCONNECTED``（info）；
    - 信号低于 :data:`WEAK_SIGNAL_PCT` → ``WIFI_SIGNAL_WEAK``（warn）；
    - ``WifiScan.available=False`` → ``WIFI_LOCATION_DENIED``（warn），detail 带原始原因；
    - 扫描结果按频段统计信道占用放进 ``rows``（键为 ``2.4GHz`` / ``5GHz`` 等）。
    """
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    system = api if api is not None else LiveSystemApi()

    errors: list[ProbeError] = []
    findings: list[Finding] = []
    rows: list[dict[str, Any]] = []

    state, state_error, state_finding = _read_state(system)
    if state_error is not None:
        errors.append(state_error)
    if state_finding is not None:
        findings.append(state_finding)
    if state is not None:
        rows.extend(_state_rows(state))
        findings.extend(_state_findings(state))

    scan, scan_error, scan_finding = _read_scan(system)
    if scan_error is not None:
        errors.append(scan_error)
    if scan_finding is not None:
        findings.append(scan_finding)
    if scan is not None:
        if scan.available:
            rows.extend(_occupancy_rows(_channel_counts(scan.networks)))
        else:
            # 扫描被位置权限拒绝：结论里保留原始原因，同时记一条可解释的探测错误。
            findings.extend(_scan_findings(scan))
            errors.append(
                ProbeError(
                    code=ProbeErrorCode.DENIED,
                    source="wlanapi",
                    message=scan.error or "周边 WiFi 扫描不可用（未提供原因）",
                )
            )

    duration_ms = round((time.perf_counter() - started) * 1000)
    section = Section(id="wifi", title="WiFi", rows=rows, findings=findings)
    return Report(
        command="wifi",
        started_at=started_at,
        duration_ms=duration_ms,
        environment=_environment(),
        sections=[section],
        findings=list(findings),
        errors=errors,
    )
