# -*- coding: utf-8 -*-
"""``netopt.commands.wifi`` 测试：FakeSystemApi → Report，不打印、不执行命令。

三类状态（已连接 / 未连接 / 扫描被拒）与信道统计都在这里覆盖；
所有系统读取一律注入 :class:`~netopt.system.api.FakeSystemApi`，不触碰真实 WLAN。
"""

from __future__ import annotations

import inspect

import pytest

from netopt.commands import wifi as wifi_mod
from netopt.commands.wifi import WEAK_SIGNAL_PCT, build_wifi_report
from netopt.domain import (
    FindingCode,
    ProbeErrorCode,
    Severity,
    WifiNetwork,
    WifiScan,
    WifiState,
)
from netopt.system import FakeSystemApi, SystemUnavailable

_BANDS = {"2.4GHz", "5GHz", "6GHz"}


def _section(report):
    return report.sections[0]


def _codes(report) -> set[str]:
    """顶层与本节结论码的并集（两条路径都要能查到）。"""
    return {finding.code for finding in report.findings} | {
        finding.code for finding in _section(report).findings
    }


def _finding(report, code: str):
    return next(finding for finding in report.findings if finding.code == code)


def _rows_by_band(report) -> dict[str, str]:
    """把 ``rows`` 里以频段为键的条目展开成 ``{频段: 占用说明}``。"""
    return {
        key: value for row in _section(report).rows for key, value in row.items() if key in _BANDS
    }


def _connected(signal: int | None = 80) -> WifiState:
    """构造一个已连接的最小 WLAN 状态。"""
    return WifiState(
        connected=True,
        interface="WLAN",
        ssid="Home",
        bssid="02:00:00:00:00:01",
        signal_pct=signal,
        channel=6,
        band="2.4GHz",
    )


def _network(channel: int | None, band: str | None, ssid: str = "net") -> WifiNetwork:
    """构造一条周边网络记录（BSSID 只用于去重展示，不参与统计）。"""
    return WifiNetwork(
        ssid=ssid,
        bssid=f"02:00:00:00:00:{channel or 0:02X}",
        signal_pct=80,
        channel=channel,
        band=band,
    )


# ===========================================================================
# 已连接 + 扫描正常
# ===========================================================================
def test_wifi_connected_reports_state_and_channel_occupancy(capsys) -> None:
    networks = [
        _network(6, "2.4GHz", "Home"),
        _network(6, "2.4GHz", "Neighbor"),
        _network(11, "2.4GHz", "Neighbor2"),
        _network(36, "5GHz", "Fast"),
    ]
    api = FakeSystemApi(wifi=_connected(80), wifi_scan=WifiScan(networks=networks))

    report = build_wifi_report(api=api)

    assert report.command == "wifi"
    assert report.schema_version == 1
    assert report.duration_ms >= 0
    assert {"admin", "python", "platform", "cwd", "api"} <= set(report.environment)
    assert report.environment["api"] == "wlanapi"
    assert report.findings == []
    assert report.errors == []

    section = _section(report)
    assert section.id == "wifi"
    assert section.title == "WiFi"
    # 当前连接信息：SSID / 信道 / 频段 / 信号
    connection = section.rows[0]
    assert connection == {
        "ssid": "Home",
        "channel": 6,
        "band": "2.4GHz",
        "signal": "80%",
    }
    # 信道占用按频段分开统计；同频段按占用降序、信道升序
    assert _rows_by_band(report) == {
        "2.4GHz": "信道6:2  信道11:1",
        "5GHz": "信道36:1",
    }
    assert capsys.readouterr().out == "", "命令层不得打印"


def test_wifi_channel_counts_sort_by_occupancy_then_channel() -> None:
    networks = [
        _network(11, "2.4GHz"),
        _network(11, "2.4GHz"),
        _network(6, "2.4GHz"),
        _network(6, "2.4GHz"),
        _network(1, "2.4GHz"),
        _network(1, "2.4GHz"),
        _network(1, "2.4GHz"),
    ]
    api = FakeSystemApi(wifi=_connected(), wifi_scan=WifiScan(networks=networks))

    report = build_wifi_report(api=api)

    assert _rows_by_band(report) == {"2.4GHz": "信道1:3  信道6:2  信道11:2"}


def test_wifi_band_is_inferred_from_channel_when_missing() -> None:
    networks = [
        _network(6, None),
        _network(6, None),
        _network(36, None),
        _network(149, None),
        _network(200, None),
        _network(None, None),  # 无信道：跳过，不猜测
    ]
    api = FakeSystemApi(wifi=_connected(), wifi_scan=WifiScan(networks=networks))

    report = build_wifi_report(api=api)

    assert _rows_by_band(report) == {
        "2.4GHz": "信道6:2",
        "5GHz": "信道36:1  信道149:1",
        "6GHz": "信道200:1",
    }


# ===========================================================================
# 未连接
# ===========================================================================
def test_wifi_disconnected_is_info_and_still_scans() -> None:
    state = WifiState(connected=False, interface="WLAN", state="disconnected")
    api = FakeSystemApi(
        wifi=state,
        wifi_scan=WifiScan(networks=[_network(1, "2.4GHz")]),
    )

    report = build_wifi_report(api=api)

    codes = _codes(report)
    assert FindingCode.WIFI_DISCONNECTED in codes
    assert FindingCode.WIFI_SIGNAL_WEAK not in codes
    finding = _finding(report, FindingCode.WIFI_DISCONNECTED)
    assert finding.severity is Severity.info
    assert "disconnected" in finding.detail
    # 未连接时不得编造当前连接的 SSID 行，但扫描结果照常统计
    assert all("ssid" not in row for row in _section(report).rows)
    assert _rows_by_band(report) == {"2.4GHz": "信道1:1"}
    assert report.errors == []


# ===========================================================================
# 信号强弱
# ===========================================================================
@pytest.mark.parametrize(
    ("signal", "weak"),
    [(0, True), (39, True), (WEAK_SIGNAL_PCT, False), (100, False)],
)
def test_wifi_signal_threshold(signal: int, weak: bool) -> None:
    api = FakeSystemApi(wifi=_connected(signal), wifi_scan=WifiScan())

    report = build_wifi_report(api=api)

    codes = _codes(report)
    assert (FindingCode.WIFI_SIGNAL_WEAK in codes) is weak
    if weak:
        finding = _finding(report, FindingCode.WIFI_SIGNAL_WEAK)
        assert finding.severity is Severity.warn
        assert f"{signal}%" in finding.detail
        assert f"{WEAK_SIGNAL_PCT}%" in finding.detail
        assert FindingCode.WIFI_DISCONNECTED not in codes


# ===========================================================================
# 扫描被拒
# ===========================================================================
def test_wifi_scan_denied_is_warn_and_keeps_original_error() -> None:
    reason = "周边 WiFi 扫描被 Windows 拒绝：当前进程没有位置权限。"
    api = FakeSystemApi(
        wifi=_connected(),
        wifi_scan=WifiScan(networks=[], available=False, error=reason),
    )

    report = build_wifi_report(api=api)

    finding = _finding(report, FindingCode.WIFI_LOCATION_DENIED)
    assert finding.severity is Severity.warn
    assert reason in finding.detail
    assert finding.evidence[0].detail == reason
    # 扫描被拒必须有可解释的探测错误，且不得伪造信道数据
    assert len(report.errors) == 1
    assert report.errors[0].code == ProbeErrorCode.DENIED
    assert report.errors[0].source == "wlanapi"
    assert reason in report.errors[0].message
    assert _rows_by_band(report) == {}
    # 当前连接信息仍然保留
    assert _section(report).rows[0]["ssid"] == "Home"


def test_wifi_scan_denied_without_error_text_still_explains() -> None:
    api = FakeSystemApi(
        wifi=WifiState(connected=False),
        wifi_scan=WifiScan(networks=[], available=False, error=None),
    )

    report = build_wifi_report(api=api)

    finding = _finding(report, FindingCode.WIFI_LOCATION_DENIED)
    assert "未提供原因" in finding.detail
    assert {FindingCode.WIFI_DISCONNECTED, FindingCode.WIFI_LOCATION_DENIED} <= _codes(report)


# ===========================================================================
# SystemApi 抛异常：转成 ProbeError，不崩
# ===========================================================================
class _BrokenScanApi(FakeSystemApi):
    """扫描抛 ``SystemUnavailable`` 的测试替身。"""

    def wifi_scan(self) -> WifiScan:
        raise SystemUnavailable("wlanapi.dll 不可用")


class _BrokenStateApi(FakeSystemApi):
    """状态读取抛 ``SystemUnavailable`` 的测试替身。"""

    def wifi(self) -> WifiState:
        raise SystemUnavailable("WlanOpenHandle 失败")


def test_wifi_scan_exception_is_recorded_without_crashing() -> None:
    api = _BrokenScanApi(wifi=_connected(), wifi_scan=WifiScan())

    report = build_wifi_report(api=api)

    assert FindingCode.SYSTEM_UNAVAILABLE in _codes(report)
    assert len(report.errors) == 1
    assert report.errors[0].code == ProbeErrorCode.UNAVAILABLE
    assert "wlanapi.dll 不可用" in report.errors[0].message
    # 状态仍然读到，连接信息照常输出
    assert _section(report).rows[0]["ssid"] == "Home"


def test_wifi_state_exception_still_reports_scan() -> None:
    api = _BrokenStateApi(
        wifi=WifiState(),
        wifi_scan=WifiScan(networks=[_network(6, "2.4GHz")]),
    )

    report = build_wifi_report(api=api)

    assert FindingCode.SYSTEM_UNAVAILABLE in _codes(report)
    assert report.errors[0].code == ProbeErrorCode.UNAVAILABLE
    assert "WlanOpenHandle" in report.errors[0].message
    assert _rows_by_band(report) == {"2.4GHz": "信道6:1"}
    assert all("ssid" not in row for row in _section(report).rows)


# ===========================================================================
# 分层约束
# ===========================================================================
def test_wifi_does_not_depend_on_diag() -> None:
    """v2 命令层不得回头依赖 v1 的 ``netopt.diag``（禁止打印 / netsh 解析）。"""
    source = inspect.getsource(wifi_mod)

    assert "netopt.diag" not in source
    assert "import diag" not in source
