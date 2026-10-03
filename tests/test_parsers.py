"""parsers 单元测试。

数据来源：

- 绝大多数用例的输入是 ``tests/fixtures/`` 里的**真实抓取样本**（见 SOURCES.md）；
- 本机产生不了的场景（英文界面、已连接的 WiFi、mode=bssid 的网络列表）用**内联的
  合成样本**补充，常量以 ``SYNTHETIC`` 开头并在注释里标明 —— 这类样本的期望值是
  人工按格式规范推定的，不是实测真值。

预期值全部独立写出（样本明文 / 手算），**不调用被测函数自身生成预期**。
每个缺陷（D1/D2/D3/D15）都有能「改回旧实现就变红」的回归用例。
"""

from __future__ import annotations

import pytest
from conftest import fixture_text

from netopt.models import ChannelOccupancy, DnsConfig, Gateway, PingStat, WlanInfo
from netopt.parsers import (
    parse_ipconfig_addresses,
    parse_ipconfig_dns,
    parse_netsh_dnsservers,
    parse_netsh_interfaces,
    parse_ping,
    parse_route_default,
    parse_wlan_interfaces,
    parse_wlan_networks,
    ping_reply_ok,
)

# ---------------------------------------------------------------------------
# 合成样本（SYNTHETIC）—— 本机抓不到的界面语言 / 已连接 WiFi / 网络列表
# ---------------------------------------------------------------------------

# SYNTHETIC：英文 Windows 的 route print。永久路由段 metric=5 < 活动段的 25，
# 是专门用来抓「两段混解析」的陷阱值。
SYNTHETIC_EN_ROUTE = """IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.0.0.254        10.0.0.5     55
          0.0.0.0          0.0.0.0        10.0.0.1         10.0.0.5     25
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0        10.0.0.1       5
===========================================================================
"""

# SYNTHETIC：英文 netsh interface ipv4 show dnsservers
SYNTHETIC_EN_NS_DNS = """Configuration for interface "Ethernet"
    DNS servers configured through DHCP:  192.168.1.1
    Register with which suffix:           Primary only

Configuration for interface "Wi-Fi"
    Statically Configured DNS Servers:  8.8.8.8
                                         8.8.4.4
    Register with which suffix:           Primary only

Configuration for interface "Loopback"
    Statically Configured DNS Servers:  None
    Register with which suffix:           None
"""

# SYNTHETIC：英文 ipconfig /all，DNS 同时有 IPv4 与 IPv6，DHCP 开着
SYNTHETIC_EN_IPCONFIG = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.1.50
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DHCP Enabled. . . . . . . . . . . : Yes
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       2001:4860:4860::8888
   NetBIOS over Tcpip. . . . . . . . : Enabled
"""

# SYNTHETIC：中文 netsh wlan show interfaces 的**已连接**形态。
# 含 BSSID 行 —— 用来证明 SSID 不会被 BSSID（MAC）顶替。
SYNTHETIC_ZH_WLAN_CONNECTED = """系统上有 1 个接口:

    名称                   : WLAN
    说明            : Example Wi-Fi 6 Wireless Adapter
    GUID                   : 00000000-0000-0000-0000-000000000001
    物理地址       : 02:00:00:00:00:05
    SSID                   : MyHomeNet
    BSSID                  : 02:00:00:00:00:0F
    网络类型               : 基础结构
    无线电类型             : 802.11ax
    状态                  : 已连接
    信号                   : 76%
    信道                   : 36
    频段                   : 5 GHz
    接收速率(Mbps)         : 144
    传输速率(Mbps)         : 130
"""

# SYNTHETIC：英文 netsh wlan show interfaces
SYNTHETIC_EN_WLAN_CONNECTED = """There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : connected
    SSID                   : CafeNet
    BSSID                  : 02:00:00:00:00:10
    Signal                 : 41%
    Channel                : 6
    Receive rate (Mbps)    : 72.2
    Transmit rate (Mbps)   : 65
"""

# SYNTHETIC：mode=bssid 的周边网络列表。
# Neighbor-24 有 2 个 BSSID（同信道 6）；Fast-5G 的 36 与 2.4G 信道互不干扰；
# NoBssidNet 没有 BSSID 子块，按网络级信道 11 计 1 次。
SYNTHETIC_WLAN_NETWORKS = """接口名称 : WLAN
当前有 3 个网络可见。

SSID 1 : Neighbor-24
    网络类型             : 基础结构
    信道                 : 6
    BSSID 1                : 02:00:00:00:00:11
         信号             : 40%
         频段             : 2.4 GHz
         信道             : 6
    BSSID 2                : 02:00:00:00:00:12
         信号             : 30%
         频段             : 2.4 GHz
         信道             : 6

SSID 2 : Fast-5G
    网络类型             : 基础结构
    信道                 : 36
    BSSID 1                : 02:00:00:00:00:13
         信号             : 70%
         频段             : 5 GHz
         信道             : 36

SSID 3 : NoBssidNet
    网络类型             : 基础结构
    信道                 : 11
"""


# ---------------------------------------------------------------------------
# D2: parse_netsh_interfaces
# ---------------------------------------------------------------------------


def test_netsh_interfaces_full_table_from_real_sample():
    """真值表逐行核对 netsh_interfaces.txt（8 个接口，原文顺序）。"""
    expected = [
        # (index, name, mtu, connected, kind, is_primary)
        (1, "Loopback Pseudo-Interface 1", 4294967295, True, "loopback", False),
        (14, "WLAN", 1500, False, "wlan", True),
        (18, "蓝牙网络连接", 1500, False, "ethernet", True),
        (2, "以太网", 1500, True, "ethernet", True),
        (41, "vEthernet (Default Switch)", 1500, True, "virtual", False),
        (13, "本地连接* 1", 1500, False, "ethernet", True),
        (7, "本地连接* 2", 1500, False, "ethernet", True),
        (23, "Example VPN", 1500, True, "vpn", True),
    ]
    got = [
        (i.index, i.name, i.mtu, i.connected, i.kind, i.is_primary)
        for i in parse_netsh_interfaces(fixture_text("netsh_interfaces"))
    ]
    assert got == expected


def test_netsh_interfaces_connected_is_exact_token_regression_d2():
    """D2 回归：状态列是小写 connected，且 disconnected 含 connected 子串。

    - 旧实现 `"Connected" in line`（大写）恒不命中 → 返回 []，本用例变红；
    - 若改成小写子串包含，WLAN/蓝牙/本地连接 会被误判已连接 → 本用例变红。
    """
    ifaces = parse_netsh_interfaces(fixture_text("netsh_interfaces"))
    connected = [i.name for i in ifaces if i.connected]
    assert connected == [
        "Loopback Pseudo-Interface 1",
        "以太网",
        "vEthernet (Default Switch)",
        "Example VPN",
    ]
    by_name = {i.name: i for i in ifaces}
    assert by_name["WLAN"].connected is False  # "disconnected" 里含 "connected"
    assert by_name["蓝牙网络连接"].connected is False
    assert by_name["本地连接* 1"].connected is False


def test_netsh_interfaces_configurable_excludes_loopback_and_virtual():
    """可配置 DNS 的接口 = 已连接且非 loopback/virtual（D2 修复后应有 2 个）。"""
    ifaces = parse_netsh_interfaces(fixture_text("netsh_interfaces"))
    assert [i.name for i in ifaces if i.configurable] == ["以太网", "Example VPN"]


def test_netsh_interfaces_loopback_mtu_not_primary():
    """环回 MTU 是 4294967295，绝不能被视为可配置接口。"""
    ifaces = parse_netsh_interfaces(fixture_text("netsh_interfaces"))
    loopback = next(i for i in ifaces if i.name == "Loopback Pseudo-Interface 1")
    assert loopback.kind == "loopback"
    assert loopback.mtu == 4294967295
    assert loopback.is_primary is False


# ---------------------------------------------------------------------------
# D1: parse_route_default
# ---------------------------------------------------------------------------


def test_route_default_picks_min_metric_from_active_routes_d1():
    """D1 回归：本机真值是 192.0.2.1 / metric 26。

    样本的陷阱：活动段第一条是 Example VPN 的 198.51.100.1（metric 9257，取第一条就错）；
    永久路由段还有 metric 9256 与 1 两行（混段解析就会拿到 1）。
    """
    gw = parse_route_default(fixture_text("route_print_default"))
    assert gw is not None
    assert gw.ip == "192.0.2.1"
    assert gw.interface_ip == "192.0.2.10"
    assert gw.metric == 26
    assert gw == Gateway(ip="192.0.2.1", interface_ip="192.0.2.10", metric=26)
    assert gw.ip != "198.51.100.1"


def test_route_default_ignores_persistent_section():
    """SYNTHETIC 英文样本：永久路段 metric=5 比活动段的 25 小，必须忽略。"""
    gw = parse_route_default(SYNTHETIC_EN_ROUTE)
    assert gw == Gateway(ip="10.0.0.1", interface_ip="10.0.0.5", metric=25)


def test_route_default_none_when_no_active_section():
    text = (
        "永久路由:\n"
        "  网络地址          网络掩码  网关地址  跃点数\n"
        "          0.0.0.0          0.0.0.0     192.0.2.1       1\n"
    )
    assert parse_route_default(text) is None
    assert parse_route_default("") is None


# ---------------------------------------------------------------------------
# D3: DNS 解析
# ---------------------------------------------------------------------------


def test_netsh_dnsservers_real_static_truth_d3():
    """D3 回归：以太网真实 DNS 是静态的 114.114.114.114 + 192.0.2.1。"""
    cfgs = parse_netsh_dnsservers(fixture_text("netsh_dnsservers"))
    by_name = {c.interface: c for c in cfgs}
    assert len(cfgs) == 8
    assert by_name["以太网"].servers == ["114.114.114.114", "192.0.2.1"]
    assert by_name["以太网"].source == "static"


def test_netsh_dnsservers_other_interfaces_all_none():
    cfgs = parse_netsh_dnsservers(fixture_text("netsh_dnsservers"))
    by_name = {c.interface: c for c in cfgs}
    for name in (
        "Example VPN",
        "WLAN",
        "本地连接* 1",
        "本地连接* 2",
        "蓝牙网络连接",
        "Loopback Pseudo-Interface 1",
        "vEthernet (Default Switch)",
    ):
        assert by_name[name].source == "none", name
        assert by_name[name].servers == [], name


def test_netsh_dnsservers_english_synthetic():
    """SYNTHETIC：英文键（Configuration for interface / Statically... / ...through DHCP）。"""
    cfgs = parse_netsh_dnsservers(SYNTHETIC_EN_NS_DNS)
    by_name = {c.interface: c for c in cfgs}
    assert by_name["Ethernet"].source == "dhcp"
    assert by_name["Ethernet"].servers == ["192.168.1.1"]
    assert by_name["Wi-Fi"].source == "static"
    assert by_name["Wi-Fi"].servers == ["8.8.8.8", "8.8.4.4"]
    assert by_name["Loopback"].source == "none"
    assert by_name["Loopback"].servers == []


def test_ipconfig_dns_keeps_ipv6_and_ipv4_d3():
    """D3 回归：ipconfig /all 的 IPv6 DNS（fe80::1%1）不能被丢掉。

    行首 fe80::1%1 在样本里出现两次，按首次出现去重后的期望是 3 个。
    旧实现只抓 IPv4 → 本用例变红。
    """
    cfgs = parse_ipconfig_dns(fixture_text("ipconfig_all"))
    assert len(cfgs) == 1
    cfg = cfgs[0]
    assert cfg.interface == "以太网"
    assert cfg.servers == ["fe80::1%1", "114.114.114.114", "192.0.2.1"]
    assert cfg.source == "static"  # 样本明文「DHCP 已启用 . : 否」


def test_ipconfig_plain_has_no_dns_rows():
    """不带 /all 的 ipconfig 里以太网只有网关、没有 DNS 行。

    这正是旧 current_dns() 在真实场景拿不到 DNS 的原因，文档化在此。
    """
    assert parse_ipconfig_dns(fixture_text("ipconfig_plain")) == []


def test_ipconfig_dns_english_synthetic():
    cfgs = parse_ipconfig_dns(SYNTHETIC_EN_IPCONFIG)
    assert len(cfgs) == 1
    assert cfgs[0].interface == "Ethernet"
    assert cfgs[0].servers == ["192.168.1.1", "2001:4860:4860::8888"]
    assert cfgs[0].source == "dhcp"  # DHCP Enabled: Yes


def test_ipconfig_addresses_real_sample():
    """适配器名 -> IPv4（无 IPv4 的适配器不出现；掩码/网关行不能混进来）。"""
    assert parse_ipconfig_addresses(fixture_text("ipconfig_plain")) == {
        "Example VPN": "198.51.100.10",
        "以太网": "192.0.2.10",
        "vEthernet (Default Switch)": "192.0.2.20",
    }


def test_ipconfig_addresses_english_synthetic():
    assert parse_ipconfig_addresses(SYNTHETIC_EN_IPCONFIG) == {"Ethernet": "192.168.1.50"}


# ---------------------------------------------------------------------------
# parse_ping
# ---------------------------------------------------------------------------


def test_parse_ping_ok_stats():
    """ping_ok.txt：4/4 回复，时间 27/26/26/26 → 手算 min 26 / max 27 / avg 26.25 / jitter 0.375。"""
    text = fixture_text("ping_ok")
    stat = parse_ping(text, "www.baidu.com", 4, code=0)
    assert isinstance(stat, PingStat)
    assert stat.replies == 4
    assert stat.min_ms == 26.0
    assert stat.max_ms == 27.0
    assert stat.avg_ms == pytest.approx(26.25)
    assert stat.jitter_ms == pytest.approx(0.375)
    assert stat.loss_pct == 0.0
    assert stat.reachable is True
    assert stat.raw == text


def test_parse_ping_all_lost():
    """ping_loss100.txt：4 发 0 收，rc=1 → 全部统计为空、loss=100。"""
    stat = parse_ping(fixture_text("ping_loss100"), "198.51.100.1", 4, code=1)
    assert stat.replies == 0
    assert stat.min_ms is None
    assert stat.avg_ms is None
    assert stat.max_ms is None
    assert stat.jitter_ms is None
    assert stat.loss_pct == 100.0
    assert stat.reachable is False


def test_parse_ping_df_fail_is_not_a_reply():
    stat = parse_ping(fixture_text("ping_df_fail"), "223.5.5.5", 1, code=1)
    assert stat.replies == 0
    assert stat.avg_ms is None
    assert stat.loss_pct == 100.0


def test_parse_ping_partial_loss_uses_caller_count():
    """SYNTHETIC：4 发 2 收 → loss 50.0；丢失率按调用方传的 count 算，不是按解析出的回复数。"""
    text = (
        "来自 1.2.3.4 的回复: time=10ms\n来自 1.2.3.4 的回复: time=20ms\n请求超时。\n请求超时。\n"
    )
    stat = parse_ping(text, "1.2.3.4", 4, code=0)
    assert stat.replies == 2
    assert stat.loss_pct == 50.0
    assert stat.min_ms == 10.0
    assert stat.avg_ms == pytest.approx(15.0)
    assert stat.max_ms == 20.0


def test_parse_ping_sub_ms_reply_is_counted():
    """SYNTHETIC：``时间<1ms`` 也是有效回复（本机常见），不能被丢掉。"""
    text = "来自 192.0.2.1 的回复: 时间<1ms\n来自 192.0.2.1 的回复: 时间=1ms\n"
    stat = parse_ping(text, "192.0.2.1", 2, code=0)
    assert stat.replies == 2
    assert stat.loss_pct == 0.0
    assert stat.min_ms == 1.0  # "<1ms" 记为 1.0（真实值的上界）


# ---------------------------------------------------------------------------
# D15: ping_reply_ok 三态
# ---------------------------------------------------------------------------


def test_ping_reply_ok_true_requires_rc0_and_rtt():
    assert ping_reply_ok(fixture_text("ping_df_ok"), 0) is True
    assert ping_reply_ok(fixture_text("ping_ok"), 0) is True


def test_ping_reply_ok_false_on_df():
    """D15 回归：DF 过大是**明确上界**，必须是 False。"""
    assert ping_reply_ok(fixture_text("ping_df_fail"), 1) is False


def test_ping_reply_ok_none_on_timeout_and_unknown_host():
    assert ping_reply_ok(fixture_text("ping_loss100"), 1) is None
    assert ping_reply_ok(fixture_text("ping_unknown_host"), 1) is None


def test_ping_reply_ok_distinguishes_df_from_timeout_same_exit_code_d15():
    """D15 核心回归：两个样本 rc 都是 1，但 DF=确定过大(False)、超时=不确定(None)。

    旧实现（含 TTL 才算通 / 布尔返回）无法区分这两者 → 本用例变红。
    """
    df = ping_reply_ok(fixture_text("ping_df_fail"), 1)
    timeout = ping_reply_ok(fixture_text("ping_loss100"), 1)
    assert df is False
    assert timeout is None
    assert df is not timeout


def test_ping_reply_ok_unreachable_reply_is_none():
    """SYNTHETIC：ICMP 目标不可达的“回复”没有往返时间，不能算通。

    旧 _ping_ok 只看 "来自"/"TTL" 子串，会把这种行判成 True。
    """
    text = "来自 192.0.2.1 的回复: 无法访问目标主机。\n"
    assert ping_reply_ok(text, 1) is None


def test_ping_reply_ok_no_reply_is_not_true_even_with_rc0():
    assert ping_reply_ok("", 0) is None
    assert ping_reply_ok("Request timed out.", 0) is None


def test_ping_reply_ok_english_df_and_timeout():
    """SYNTHETIC：英文报文的 DF / 超时形态。"""
    assert ping_reply_ok("Packet needs to be fragmented but DF set.", 1) is False
    assert ping_reply_ok("Request timed out.", 1) is None


# ---------------------------------------------------------------------------
# WLAN
# ---------------------------------------------------------------------------


def test_wlan_interfaces_real_disconnected():
    info = parse_wlan_interfaces(fixture_text("wlan_interfaces"))
    assert info.connected is False
    assert info.interface == "WLAN"
    assert info.state == "已断开连接"
    assert info.ssid is None
    assert info.signal_pct is None
    assert info.channel is None
    assert info.band is None
    assert info.rx_mbps is None
    assert info.tx_mbps is None


def test_wlan_interfaces_connected_chinese_synthetic():
    """SYNTHETIC：中文已连接形态。76% -> 76；SSID 不能被 BSSID（MAC）顶替。"""
    info = parse_wlan_interfaces(SYNTHETIC_ZH_WLAN_CONNECTED)
    assert info.connected is True
    assert info.ssid == "MyHomeNet"
    assert info.signal_pct == 76
    assert info.channel == 36
    assert info.band == "5 GHz"
    assert info.rx_mbps == 144.0
    assert info.tx_mbps == 130.0
    assert info.state == "已连接"
    assert info.interface == "WLAN"


def test_wlan_interfaces_connected_english_synthetic():
    """SYNTHETIC：英文键（Name/State/SSID/Signal/Channel/Receive rate）。"""
    info = parse_wlan_interfaces(SYNTHETIC_EN_WLAN_CONNECTED)
    assert info.connected is True
    assert info.ssid == "CafeNet"
    assert info.signal_pct == 41
    assert info.channel == 6
    assert info.rx_mbps == 72.2
    assert info.tx_mbps == 65.0


def test_wlan_networks_permission_denied_is_empty():
    """真实样本 wlan_networks.txt 是「需要位置权限」提示（rc=1）→ 必须空且不崩。"""
    occ = parse_wlan_networks(fixture_text("wlan_networks"))
    assert isinstance(occ, ChannelOccupancy)
    assert occ.empty is True
    assert occ.by_band == {}
    assert occ.current_channel is None
    assert occ.current_band is None


def test_wlan_networks_separates_bands():
    """SYNTHETIC：2.4G 与 5G 分开统计，同号信道互不干扰。

    Neighbor-24 两个 BSSID 都在 2.4G ch6 → {6: 2}；
    NoBssidNet 无 BSSID 子块按网络级 ch11 计 1；
    Fast-5G 在 5G ch36。
    """
    occ = parse_wlan_networks(SYNTHETIC_WLAN_NETWORKS)
    assert occ.by_band == {"2.4GHz": {6: 2, 11: 1}, "5GHz": {36: 1}}
    assert occ.busiest("2.4GHz") == [(6, 2), (11, 1)]
    assert occ.busiest("5GHz") == [(36, 1)]
    # 5G 的 36 不能被并进 2.4G 的计数里
    assert 36 not in occ.by_band["2.4GHz"]
    assert set(occ.by_band) == {"2.4GHz", "5GHz"}


def test_wlan_networks_empty_text():
    occ = parse_wlan_networks("")
    assert occ.empty is True
    assert occ.by_band == {}


# ---------------------------------------------------------------------------
# 畸形输入：不抛异常、不造数据
# ---------------------------------------------------------------------------


def test_parsers_survive_garbage_input():
    junk = "这不是任何已知命令的输出\n随机文本 : 42\n"
    assert parse_netsh_interfaces(junk) == []
    assert parse_route_default(junk) is None
    assert parse_ipconfig_dns(junk) == []
    assert parse_netsh_dnsservers(junk) == []
    assert parse_ipconfig_addresses(junk) == {}
    assert parse_wlan_interfaces(junk) == WlanInfo()
    assert parse_wlan_networks(junk).empty is True
    assert parse_ping(junk, "x", 3, code=1).loss_pct == 100.0
    assert ping_reply_ok(junk, 1) is None


def test_dnsconfig_shape_from_netsh():
    """DnsConfig 契约：index 为 None 由 netsh 输出决定，servers 顺序保持原文。"""
    cfgs = parse_netsh_dnsservers(fixture_text("netsh_dnsservers"))
    eth = next(c for c in cfgs if c.interface == "以太网")
    assert eth == DnsConfig(
        interface="以太网", servers=["114.114.114.114", "192.0.2.1"], source="static"
    )
