# -*- coding: utf-8 -*-
"""netopt.diag 测试：渲染函数用**构造数据**，端到端用 fake_run + 真实 fixture。

安全底线：绝不真实执行系统命令（conftest 的 autouse 夹具会拦截漏注入的调用）。
测速（HTTP 下载/上传）与 ``dns_query`` / ``http_ttfb``（socket）在本文件内
monkeypatch 掉，**不联网**。

样本来源见 ``tests/fixtures/SOURCES.md``；本文件里内联的 WiFi 网络列表是
**合成样本**（本机 WLAN 未连接，抓不到真实列表），期望值由我按格式规范手工推定。
"""

from __future__ import annotations

import time

import pytest
from conftest import fixture_text

from netopt import diag, probes, state
from netopt.models import ChannelOccupancy, DnsConfig, MtuResult, PingStat, WlanInfo
from netopt.platform import CmdResult


# ===========================================================================
# 渲染层：ping 统计行
# ===========================================================================
def test_render_stat_line_unreachable() -> None:
    stat = PingStat(target="198.51.100.1", loss_pct=100.0, replies=0)
    line = diag.render_stat_line("网关 198.51.100.1", stat, 5, 30)
    assert "不可达" in line
    assert "平均" not in line


def test_render_stat_line_loss_warning_beats_latency_tag() -> None:
    stat = PingStat(target="x", avg_ms=10.0, loss_pct=25.0, replies=3)
    line = diag.render_stat_line("x", stat, 30, 100)
    assert "有丢包!" in line
    assert "正常" not in line


@pytest.mark.parametrize(
    ("avg", "expect"),
    [(10.0, "正常"), (30.0, "正常"), (30.1, "偏慢"), (100.0, "偏慢"), (100.1, "很慢")],
)
def test_render_stat_line_thresholds(avg: float, expect: str) -> None:
    stat = PingStat(target="x", avg_ms=avg, loss_pct=0.0, replies=4)
    assert expect in diag.render_stat_line("x", stat, 30, 100)


# ===========================================================================
# 渲染层：MTU 分档（D6）
# ===========================================================================
@pytest.mark.parametrize(
    ("mtu", "expect"),
    [
        (1500, "标准 1500, 正常"),
        (1501, "标准 1500, 正常"),
        (1499, "略低"),
        (1400, "略低"),
        (1399, "偏低"),
    ],
)
def test_render_mtu_line_bands(mtu: int, expect: str) -> None:
    line = diag.render_mtu_line(MtuResult(mtu=mtu, payload=mtu - 28, verified=True))
    assert expect in line
    assert f"MTU: {mtu}" in line


def test_render_mtu_line_pppoe_1492_is_not_standard() -> None:
    """D6 回归：本机真值 MTU=1492 必须报 PPPoE，绝不能报「标准 1500」。"""
    line = diag.render_mtu_line(MtuResult(mtu=1492, payload=1464, verified=True))
    assert "PPPoE" in line
    assert "1492" in line
    assert "标准 1500" not in line


def test_render_mtu_line_unverified_notes_caveat() -> None:
    line = diag.render_mtu_line(MtuResult(mtu=1492, payload=1464, verified=False))
    assert "仅供参考" in line
    # 确认过的探测不应带这个提示
    assert "仅供参考" not in diag.render_mtu_line(MtuResult(mtu=1492, payload=1464, verified=True))


def test_render_mtu_line_not_found() -> None:
    assert "探测失败" in diag.render_mtu_line(MtuResult())


# ===========================================================================
# 渲染层：DNS / HTTP
# ===========================================================================
@pytest.mark.parametrize(
    ("avg", "expect"),
    [(10.0, "10.0 ms"), (30.0, "30.0 ms"), (100.0, "100.0 ms")],
)
def test_render_dns_row_success(avg: float, expect: str) -> None:
    line = diag.render_dns_row(1, "阿里 AliDNS", "223.5.5.5", avg)
    assert expect in line
    assert "223.5.5.5" in line


def test_render_dns_row_timeout() -> None:
    assert "超时/不可达" in diag.render_dns_row(7, "OpenDNS", "208.67.222.222", None)


@pytest.mark.parametrize(
    ("ttfb", "expect"),
    [(42.0, "42.0 ms"), (150.0, "150.0 ms"), (200.0, "200.0 ms"), (500.0, "500.0 ms")],
)
def test_render_http_row_success(ttfb: float, expect: str) -> None:
    line = diag.render_http_row("百度", "www.baidu.com", ttfb)
    assert expect in line
    assert "www.baidu.com" in line


def test_render_http_row_connection_failed() -> None:
    assert "连接失败" in diag.render_http_row("腾讯", "www.qq.com", None)


def test_render_dns_status_line_uses_first_two_servers() -> None:
    line = diag.render_dns_status_line(["1.1.1.1", "2.2.2.2", "3.3.3.3"], 12.0)
    assert "1.1.1.1, 2.2.2.2" in line
    assert "3.3.3.3" not in line
    assert "12 ms 正常" in line


def test_render_dns_status_line_no_servers() -> None:
    line = diag.render_dns_status_line([], None)
    assert "未检测到 DNS 配置" in line


def test_render_dns_status_line_failure_suggests_fix() -> None:
    line = diag.render_dns_status_line(["1.1.1.1"], None)
    assert "DNS 解析失败" in line
    assert "fix dns" in line


def test_collect_dns_servers_dedups_preserving_order() -> None:
    configs = [
        DnsConfig(interface="以太网", servers=["114.114.114.114", "192.0.2.1"]),
        DnsConfig(interface="WLAN", servers=["192.0.2.1", "223.5.5.5"]),
        DnsConfig(interface="蓝牙", servers=[]),
        DnsConfig(interface="vEthernet", servers=[]),
    ]
    assert diag.collect_dns_servers(configs) == [
        "114.114.114.114",
        "192.0.2.1",
        "223.5.5.5",
    ]
    assert diag.collect_dns_servers([]) == []


# ===========================================================================
# 渲染层：测速（D4 / D10）
# ===========================================================================
def test_render_speed_downloads_picks_best_and_reports_skips() -> None:
    samples = [
        diag.SpeedSample("Cloudflare", 66.0),
        diag.SpeedSample("阿里云镜像", None, "URLError: [WinError 10061] 连接被拒绝"),
        diag.SpeedSample("清华镜像", 77.5),
    ]
    text = "\n".join(diag.render_speed_downloads(samples))
    assert "测速源: 清华镜像" in text
    assert "77.50 Mbps" in text
    assert "跳过 阿里云镜像" in text
    assert "10061" in text


def test_render_speed_downloads_all_failed() -> None:
    samples = [
        diag.SpeedSample("Cloudflare", None, "超时"),
        diag.SpeedSample("阿里云镜像", None, "连接被拒绝"),
    ]
    text = "\n".join(diag.render_speed_downloads(samples))
    assert "所有测速源不可达" in text
    assert "跳过 Cloudflare" in text
    assert "跳过 阿里云镜像" in text


def test_render_speed_upload_failure_does_not_crash() -> None:
    """D4：上传失败（mbps=None）只提示跳过，绝不抛 TypeError。"""
    lines = diag.render_speed_upload(diag.SpeedSample("Cloudflare", None, "URLError: timed out"))
    text = "\n".join(lines)
    assert "上传测速失败" in text
    assert "已跳过" in text
    assert "timed out" in text


def test_render_speed_log_tolerates_failed_upload() -> None:
    """D4 回归：旧实现 f"{up:.2f}" 在 up=None 时抛 TypeError。"""
    line = diag.render_speed_log(
        diag.SpeedSample("Cloudflare", 42.5), diag.SpeedSample("Cloudflare", None, "超时")
    )
    assert "下载 42.50Mbps(Cloudflare)" in line
    assert "上传 失败" in line


def test_render_speed_log_tolerates_both_failed() -> None:
    line = diag.render_speed_log(None, diag.SpeedSample("Cloudflare", None))
    assert "下载 失败" in line
    assert "上传 失败" in line


def test_speed_sources_are_not_the_two_measured_dead_urls() -> None:
    """D10 回归守卫：旧实现里实测已死的两个 URL 不得再出现。"""
    urls = [url for _name, url in diag.SPEED_DOWNLOADS]
    assert not any("centos/7" in url for url in urls)
    assert not any("ubuntu-24.04.2" in url for url in urls)
    assert all(url.startswith("https://") for url in urls)
    assert len(urls) >= 3
    assert diag.SPEED_UPLOAD[1].startswith("https://")


# ===========================================================================
# 渲染层：WiFi（D16）
# ===========================================================================
def test_render_wlan_status_connected() -> None:
    info = WlanInfo(
        connected=True,
        ssid="MyWiFi",
        signal_pct=80,
        channel=36,
        band="5 GHz",
        rx_mbps=866.7,
        tx_mbps=866.7,
        state="已连接",
        interface="WLAN",
    )
    text = "\n".join(diag.render_wlan_status(info, CmdResult(argv=[], code=0, out="")))
    assert "SSID: MyWiFi" in text
    assert "80% 良好" in text
    assert "信道: 36" in text
    assert "接收速率: 866.7 Mbps" in text


@pytest.mark.parametrize(
    ("signal", "expect"), [(70, "70% 良好"), (69, "69% 一般"), (40, "40% 一般"), (39, "39% 差")]
)
def test_render_wlan_status_signal_bands(signal: int, expect: str) -> None:
    info = WlanInfo(connected=True, ssid="X", signal_pct=signal, state="已连接")
    text = "\n".join(diag.render_wlan_status(info, CmdResult(argv=[], code=0, out="")))
    assert expect in text


def test_render_wlan_status_disconnected() -> None:
    info = WlanInfo(connected=False, state="已断开连接", interface="WLAN")
    text = "\n".join(diag.render_wlan_status(info, CmdResult(argv=[], code=0, out="")))
    assert "未连接到任何 WiFi" in text
    assert "已断开连接" in text
    assert "WLAN" in text


def test_render_wlan_status_command_failure_is_not_mistaken_for_disconnected() -> None:
    res = CmdResult(argv=["netsh"], code=1, out="请求的操作需要提升(作为管理员运行)。")
    text = "\n".join(diag.render_wlan_status(WlanInfo(), res))
    assert "无法读取 WiFi 状态" in text
    assert "rc=1" in text
    assert "未连接到任何 WiFi" not in text


def test_render_wlan_scan_location_permission_explains_how_to_fix() -> None:
    """D16：拿到 rc=1 后必须说明原因与开启方式（真实权限失败样本）。"""
    res = CmdResult(argv=["netsh"], code=1, out=fixture_text("wlan_networks"))
    text = "\n".join(diag.render_wlan_scan(res, ChannelOccupancy()))
    assert "无法获取周边网络列表" in text
    assert "rc=1" in text
    assert "位置" in text
    assert "ms-settings:privacy-location" in text


def test_render_wlan_scan_admin_hint_when_only_elevation_requested() -> None:
    res = CmdResult(argv=["netsh"], code=1, out="请求的操作需要提升(作为管理员运行)。")
    text = "\n".join(diag.render_wlan_scan(res, ChannelOccupancy()))
    assert "管理员" in text


def test_render_wlan_scan_ok_but_empty_is_explicit() -> None:
    res = CmdResult(argv=["netsh"], code=0, out="")
    text = "\n".join(diag.render_wlan_scan(res, ChannelOccupancy()))
    assert "未扫描到周边 WiFi 网络" in text


def test_render_channel_occupancy_separates_bands_and_ranks_current() -> None:
    occ = ChannelOccupancy(
        by_band={"2.4GHz": {6: 3, 11: 1}, "5GHz": {36: 2}},
        current_channel=6,
        current_band="2.4GHz",
    )
    text = "\n".join(diag.render_channel_occupancy(occ))
    assert "2.4GHz" in text and "5GHz" in text
    assert "信道6:3" in text
    assert "信道36:2" in text
    assert "当前信道 6 (2.4GHz) 拥堵排名第 1" in text
    # 当前信道被 3 个网络占用，11 只有 1 个 → 建议换到 11
    assert "建议: 路由器可尝试换到空闲信道 11" in text


def test_render_channel_occupancy_no_suggestion_when_current_is_free() -> None:
    occ = ChannelOccupancy(
        by_band={"2.4GHz": {6: 1, 11: 4}}, current_channel=6, current_band="2.4GHz"
    )
    text = "\n".join(diag.render_channel_occupancy(occ))
    assert "拥堵排名第 2" in text
    assert "建议" not in text


# ===========================================================================
# 渲染层：monitor
# ===========================================================================
@pytest.mark.parametrize(
    ("rtt", "expect"), [(50.0, "50.0 ms"), (150.0, "150.0 ms"), (350.0, "350.0 ms")]
)
def test_render_monitor_tick(rtt: float, expect: str) -> None:
    line = diag.render_monitor_tick(1, 3, rtt)
    assert line.startswith("\r")
    assert "第   1/3 次" in line
    assert expect in line


def test_render_monitor_tick_timeout() -> None:
    assert "超时" in diag.render_monitor_tick(2, 60, None)


def test_render_monitor_summary_statistics_and_burst_hint() -> None:
    samples = [10.0, 20.0, 30.0, 400.0, 410.0, 420.0]
    text = "\n".join(diag.render_monitor_summary(samples, loss=2))
    assert "采样 6 次" in text
    assert "最低 10.0 ms" in text
    assert "最高 420.0 ms" in text
    assert "平均 215.0 ms" in text
    assert "抖动 195.0 ms" in text
    assert "丢包 2 次" in text
    assert "最大连续高延迟(>200ms): 3 次" in text
    assert "持续高延迟" in text


def test_render_monitor_summary_no_hint_below_three_bursts() -> None:
    text = "\n".join(diag.render_monitor_summary([100.0, 300.0, 100.0], loss=0))
    assert "最大连续高延迟(>200ms): 1 次" in text
    assert "建议" not in text


def test_render_monitor_summary_all_timeout() -> None:
    assert "全部超时，网络不可用" in "\n".join(diag.render_monitor_summary([], loss=5))


# ===========================================================================
# 端到端：fake_run + 真实 fixture
# ===========================================================================
def _mtu_branch(limit: int = 1464):
    """按 payload 分支的假 ping（fake_run 只支持固定前缀，无法按 -l 分支）。"""
    ok_text = fixture_text("ping_df_ok")
    fail_text = fixture_text("ping_df_fail")

    def _run(argv, timeout=30.0, **kwargs):
        payload = int(argv[argv.index("-l") + 1])
        if payload <= limit:
            return CmdResult(argv=list(argv), code=0, out=ok_text.replace("1464", str(payload)))
        return CmdResult(argv=list(argv), code=1, out=fail_text.replace("1472", str(payload)))

    return _run


def _status_runner():
    """status 端到端：route/ping/netsh 走真实样本，MTU 走分支假 ping。"""
    mtu_run = _mtu_branch()

    def _run(argv, timeout=30.0, **kwargs):
        argv = list(argv)
        if argv[0] == "route":
            return CmdResult(argv=argv, code=0, out=fixture_text("route_print_default"))
        if argv[0] == "netsh":
            return CmdResult(argv=argv, code=0, out=fixture_text("netsh_dnsservers"))
        if argv[0] == "ping" and "-l" in argv:
            return mtu_run(argv, timeout, **kwargs)
        if argv[0] == "ping":
            return CmdResult(argv=argv, code=0, out=fixture_text("ping_ok"))
        raise AssertionError(f"未预期的命令: {argv!r}")

    return _run


def test_cmd_ping_gateway_from_route_and_target_stats(fake_run, capsys) -> None:
    run = fake_run(
        {
            ("route", "print"): (fixture_text("route_print_default"), 0),
            ("ping",): (fixture_text("ping_ok"), 0),
        }
    )
    diag.cmd_ping("www.baidu.com", run=run)
    out = capsys.readouterr().out

    assert "== 延迟测试: www.baidu.com ==" in out
    # D1：网关必须来自 route 的最小 metric（192.0.2.1），不是 ipconfig 第一个
    assert "网关 192.0.2.1" in out
    assert "198.51.100.1" not in out
    # ping_ok.txt 真值：27/26/26/26 → 平均 26.2、最低 26.0、最高 27.0
    assert "平均" in out and "26.2 ms" in out
    assert "最低 26.0 ms" in out
    assert "最高 27.0 ms" in out


def test_cmd_status_end_to_end_includes_pppoe_mtu(fake_run, capsys, monkeypatch) -> None:
    monkeypatch.setattr(probes, "dns_query", lambda *a, **k: 12.0)
    monkeypatch.setattr(probes, "http_ttfb", lambda *a, **k: 42.0)

    diag.cmd_status(run=_status_runner())
    out = capsys.readouterr().out

    assert "== 快速诊断 ==" in out
    assert "网关 192.0.2.1" in out
    assert "114.114.114.114" in out
    assert "DNS 解析  当前 114.114.114.114, 192.0.2.1" in out
    assert "12 ms 正常" in out
    assert "42 ms 正常" in out
    # D6：本机真值 1492 必须是 PPPoE，且不得同时出现「标准 1500」
    assert "MTU: 1492" in out
    assert "PPPoE" in out
    assert "标准 1500" not in out


def test_cmd_status_logs_summary(fake_run, capsys, monkeypatch, _isolate_state) -> None:
    monkeypatch.setattr(probes, "dns_query", lambda *a, **k: 12.0)
    monkeypatch.setattr(probes, "http_ttfb", lambda *a, **k: 42.0)

    diag.cmd_status(run=_status_runner())
    log_file = _isolate_state / f"log-{time.strftime('%Y-%m-%d')}.log"
    text = log_file.read_text(encoding="utf-8")
    assert "status: 网关26.2ms 百度26.2ms" in text


def test_cmd_dns_ranks_by_latency(fake_run, capsys, monkeypatch) -> None:
    timings = {"223.5.5.5": 10.0, "119.29.29.29": 20.0}
    monkeypatch.setattr(probes, "dns_query", lambda server, host, timeout=3.0: timings.get(server))

    run = fake_run(
        {("netsh", "interface", "ipv4", "show", "dnsservers"): fixture_text("netsh_dnsservers")}
    )
    diag.cmd_dns(run=run)
    out = capsys.readouterr().out

    assert "当前系统 DNS: 114.114.114.114, 192.0.2.1" in out
    assert "超时/不可达" in out
    assert out.index("阿里 AliDNS") < out.index("腾讯 DNSPod") < out.index("114 DNS")


def test_cmd_http_reports_rows_and_failures(capsys, monkeypatch) -> None:
    latencies = {
        "www.baidu.com": 42.0,
        "www.qq.com": None,
        "www.bilibili.com": 600.0,
        "www.microsoft.com": 200.0,
    }
    monkeypatch.setattr(probes, "http_ttfb", lambda host, port=443, timeout=5.0: latencies[host])

    diag.cmd_http()
    out = capsys.readouterr().out

    assert "== HTTP 延迟测试 (HTTPS 首字节 TTFB) ==" in out
    assert "42.0 ms" in out
    assert "连接失败" in out
    assert "600.0 ms" in out
    assert "200.0 ms" in out


def test_cmd_wifi_reports_location_permission_failure(fake_run, capsys) -> None:
    """D16 回归：rc=1 时不得静默空白，必须说明原因与开启方式；旧实现这里啥都不打。"""
    run = fake_run(
        {
            ("netsh", "wlan", "show", "interfaces"): fixture_text("wlan_interfaces"),
            ("netsh", "wlan", "show", "networks"): (fixture_text("wlan_networks"), 1),
        }
    )
    diag.cmd_wifi(run=run)
    out = capsys.readouterr().out

    assert "== WiFi 状态 ==" in out
    assert "未连接到任何 WiFi" in out
    assert "== 周边网络与信道占用 ==" in out
    assert "无法获取周边网络列表" in out
    assert "rc=1" in out
    assert "位置" in out
    assert "ms-settings:privacy-location" in out
    # 失败时不得编造/展示任何信道数据
    assert "信道" not in out.split("== 周边网络与信道占用 ==")[1]


# 合成样本（非实测）：本机 WLAN 未连接，抓不到真实网络列表。
# 手工推定的占用：2.4GHz 信道 6×2、信道 11×1；5GHz 信道 36×1。
_WLAN_NETWORKS_SYNTHETIC = """
SSID 1 : HomeWiFi
    网络类型             : 基础结构
    BSSID 1                 : 02:00:00:00:00:0B
         信道             : 6
         频段             : 2.4 GHz

SSID 2 : OtherWiFi
    网络类型             : 基础结构
    BSSID 1                 : 02:00:00:00:00:0C
         信道             : 6
    BSSID 2                 : 02:00:00:00:00:0D
         信道             : 11

SSID 3 : FastWiFi
    网络类型             : 基础结构
    BSSID 1                 : 02:00:00:00:00:0E
         信道             : 36
"""


def test_cmd_wifi_scan_success_shows_channel_occupancy(fake_run, capsys) -> None:
    run = fake_run(
        {
            ("netsh", "wlan", "show", "interfaces"): fixture_text("wlan_interfaces"),
            ("netsh", "wlan", "show", "networks"): (_WLAN_NETWORKS_SYNTHETIC, 0),
        }
    )
    diag.cmd_wifi(run=run)
    out = capsys.readouterr().out

    assert "信道6:2" in out
    assert "信道11:1" in out
    assert "5GHz" in out
    assert "信道36:1" in out


def test_cmd_speed_survives_upload_failure(fake_run, capsys, monkeypatch, _isolate_state) -> None:
    """D4 回归：下载成功 + 上传失败。旧实现在日志行 f"{up:.2f}" 抛 TypeError。"""
    monkeypatch.setattr(
        diag,
        "_download_sample",
        lambda name, url, max_seconds=15.0: diag.SpeedSample(name, 88.0),
    )
    monkeypatch.setattr(
        diag,
        "_upload_sample",
        lambda name, url, max_seconds=15.0: diag.SpeedSample(name, None, "URLError: timed out"),
    )

    diag.cmd_speed()
    out = capsys.readouterr().out

    assert "88.00 Mbps" in out
    assert "测速源: Cloudflare" in out
    assert "上传测速失败" in out
    assert "timed out" in out

    log_file = _isolate_state / f"log-{time.strftime('%Y-%m-%d')}.log"
    assert "speed: 下载 88.00Mbps(Cloudflare) 上传 失败" in log_file.read_text(encoding="utf-8")


def test_cmd_speed_skips_dead_source_and_names_live_source(capsys, monkeypatch) -> None:
    """D10：死源只跳过并给出原因，其余源继续测，结果标明用了哪个源。"""
    attempted: list[str] = []

    def fake_download(name, url, max_seconds=15.0):
        attempted.append(name)
        if name == "阿里云镜像":
            return diag.SpeedSample(name, None, "URLError: [WinError 10061] 连接被拒绝")
        if name == "Cloudflare":
            return diag.SpeedSample(name, 66.0)
        return diag.SpeedSample(name, 77.0)

    monkeypatch.setattr(diag, "_download_sample", fake_download)
    monkeypatch.setattr(
        diag, "_upload_sample", lambda *a, **k: diag.SpeedSample("Cloudflare", 10.0)
    )

    diag.cmd_speed()
    out = capsys.readouterr().out

    assert attempted == ["Cloudflare", "阿里云镜像", "清华镜像"]
    assert "测速源: 清华镜像" in out
    assert "跳过 阿里云镜像" in out
    assert "10061" in out
    assert "下载测速失败" not in out


def test_cmd_monitor_progress_and_summary(fake_run, capsys, monkeypatch) -> None:
    monkeypatch.setattr(diag.time, "sleep", lambda _seconds: None)
    run = fake_run({("ping",): (fixture_text("ping_ok"), 0)})

    diag.cmd_monitor(count=3, run=run)
    out = capsys.readouterr().out

    assert "第   1/3 次" in out
    assert "第   3/3 次" in out
    assert "采样 3 次" in out
    assert "丢包 0 次" in out


def test_cmd_monitor_all_timeout(fake_run, capsys, monkeypatch) -> None:
    monkeypatch.setattr(diag.time, "sleep", lambda _seconds: None)
    run = fake_run({("ping",): (fixture_text("ping_loss100"), 1)})

    diag.cmd_monitor(count=2, run=run)
    out = capsys.readouterr().out

    assert "超时" in out
    assert "全部超时，网络不可用" in out


def test_cmd_monitor_stop_event(fake_run, capsys, monkeypatch) -> None:
    monkeypatch.setattr(diag.time, "sleep", lambda _seconds: None)
    run = fake_run({("ping",): (fixture_text("ping_ok"), 0)})

    class _Stop:
        def __init__(self) -> None:
            self.calls = 0

        def is_set(self) -> bool:
            self.calls += 1
            return self.calls > 1

    diag.cmd_monitor(count=60, stop_event=_Stop(), run=run)
    out = capsys.readouterr().out

    assert "第   1/60 次" in out
    assert "已手动停止" in out
    assert "采样 1 次" in out


def test_cmd_trace_uses_expected_argv_and_prints_output(fake_run, capsys) -> None:
    text = "  1     1 ms   192.0.2.1\n  2    10 ms   100.1.1.1\n"
    run = fake_run({("tracert",): (text, 0)})

    diag.cmd_trace("www.baidu.com", run=run)
    out = capsys.readouterr().out

    assert "== 路由追踪: www.baidu.com (最多 20 跳) ==" in out
    assert "192.0.2.1" in out
    assert run.calls[0] == ["tracert", "-d", "-h", "20", "-w", "800", "www.baidu.com"]


def test_cmd_trace_reports_failure_without_crashing(fake_run, capsys) -> None:
    run = fake_run({("tracert",): CmdResult(argv=["tracert"], code=-1, out="", timed_out=True)})

    diag.cmd_trace("www.baidu.com", run=run)
    out = capsys.readouterr().out

    assert "未正常完成" in out
    assert "超时" in out


def test_cmd_ping_uses_default_target_and_logs(fake_run, capsys, _isolate_state) -> None:
    run = fake_run(
        {
            ("route", "print"): (fixture_text("route_print_default"), 0),
            ("ping",): (fixture_text("ping_ok"), 0),
        }
    )
    diag.cmd_ping(None, run=run)
    out = capsys.readouterr().out

    assert "== 延迟测试: www.baidu.com ==" in out
    log_file = _isolate_state / f"log-{time.strftime('%Y-%m-%d')}.log"
    assert "ping www.baidu.com: 网关 26.2ms/丢包0.0%" in log_file.read_text(encoding="utf-8")


def test_state_log_isolated(_isolate_state) -> None:
    """确认 conftest 的状态隔离对 netopt.state 生效（本文件依赖它写日志断言）。"""
    state.log("diag-test")
    log_file = _isolate_state / f"log-{time.strftime('%Y-%m-%d')}.log"
    assert "diag-test" in log_file.read_text(encoding="utf-8")
