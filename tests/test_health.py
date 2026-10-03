# -*- coding: utf-8 -*-
"""netopt.health 测试：评分边界（D6/D8）、渲染文案、端到端编排。

约定（BRIEF §8）：

- 预期值来自构造数据 + ``health.py`` 文档里的评分规则**独立手算**（算式写在
  注释里），不拿被测函数的输出反过来当预期；
- 端到端一律注入 fake runner；``probes.dns_query`` / ``probes.http_ttfb`` 是
  socket 探测，在测试内 monkeypatch 掉，绝不真实联网；
- conftest 的 autouse 夹具会拦下任何漏注入的 ``platform.run`` 调用——端到端
  测试能跑通本身就证明 ``run`` 被一路传到了 probes。
"""

from __future__ import annotations

import json

import pytest
from conftest import fixture_text

from netopt import health, probes, state
from netopt.health import ItemScore
from netopt.models import DnsConfig, Interface, MtuResult, PingStat
from netopt.platform import CmdResult

_MTU_LIMIT = 1464  # 本机真值：payload 1464 通、1465 起 DF 失败 → MTU 1492


def stat(avg_ms: float | None = None, loss_pct: float = 0.0) -> PingStat:
    """构造一次 ping 结果（有 avg_ms 视为收到了回复）。"""
    return PingStat(
        target="test",
        avg_ms=avg_ms,
        loss_pct=loss_pct,
        replies=0 if avg_ms is None else 4,
    )


def _items(*pairs: tuple[int, int]) -> list[ItemScore]:
    return [
        ItemScore(label=f"L{i}", score=score, weight=weight, detail="d")
        for i, (score, weight) in enumerate(pairs)
    ]


# ===========================================================================
# score_linear —— 所有线性维度的公共原语
# ===========================================================================
class TestScoreLinear:
    def test_none_is_zero(self) -> None:
        assert health.score_linear(None, 5, 50, 15) == 0

    def test_bounds_are_inclusive(self) -> None:
        assert health.score_linear(5, 5, 50, 15) == 15
        assert health.score_linear(4, 5, 50, 15) == 15
        assert health.score_linear(50, 5, 50, 15) == 0
        assert health.score_linear(80, 5, 50, 15) == 0

    def test_midpoint_is_linear(self) -> None:
        # (50-28)/45*15 = 7.33 → 7
        assert health.score_linear(28, 5, 50, 15) == 7


# ===========================================================================
# D8：网关评分（延迟分 + 明确的丢包折扣，取代「先 +5 再清零」的死代码）
# ===========================================================================
class TestScoreGateway:
    def test_no_loss_keeps_delay_score(self) -> None:
        assert health.score_gateway(stat(avg_ms=5, loss_pct=0)) == 15

    def test_loss_at_tolerance_boundary_keeps_full_delay_score(self) -> None:
        assert health.score_gateway(stat(avg_ms=5, loss_pct=2)) == 15

    def test_loss_just_over_tolerance_halves_delay_score(self) -> None:
        # 旧实现：先 +5 再被下一行清零 → 0。本条改回旧行为即变红。
        assert health.score_gateway(stat(avg_ms=5, loss_pct=3)) == 7

    def test_loss_25pct_halves_delay_score(self) -> None:
        # D8 的原始复现点：旧实现 (15+5) 之后 s=0；新规则 15//2 = 7。
        assert health.score_gateway(stat(avg_ms=5, loss_pct=25)) == 7

    def test_loss_at_unusable_boundary_is_zero(self) -> None:
        assert health.score_gateway(stat(avg_ms=5, loss_pct=50)) == 0

    def test_total_loss_is_zero_even_with_measured_rtt(self) -> None:
        # 构造出的矛盾数据（100% 丢包却有 RTT）也必须 0 分，不能被延迟分兜过去
        assert health.score_gateway(stat(avg_ms=5, loss_pct=100)) == 0

    def test_unreachable_is_zero(self) -> None:
        assert health.score_gateway(stat(avg_ms=None, loss_pct=100)) == 0

    def test_slow_gateway_has_no_delay_score(self) -> None:
        assert health.score_gateway(stat(avg_ms=50, loss_pct=0)) == 0
        assert health.score_gateway(stat(avg_ms=49, loss_pct=0)) == 0  # round(0.33) = 0


# ===========================================================================
# D6：MTU 评分（门槛是 MTU 本体 1500，不是 payload 1472）
# ===========================================================================
class TestScoreMtu:
    def test_standard_ethernet_is_full(self) -> None:
        assert health.score_mtu(MtuResult(mtu=1500, payload=1472, verified=True)) == 10

    def test_pppoe_1492_is_not_full(self) -> None:
        # 旧实现 _score_linear(-1492, -1472, -1200, 10) → 10 分；本条会让它变红。
        assert health.score_mtu(MtuResult(mtu=1492, payload=1464, verified=True)) == 8

    def test_band_boundaries(self) -> None:
        assert health.score_mtu(MtuResult(mtu=1499)) == 8
        assert health.score_mtu(MtuResult(mtu=1492)) == 8
        assert health.score_mtu(MtuResult(mtu=1491)) == 5
        assert health.score_mtu(MtuResult(mtu=1400)) == 5
        assert health.score_mtu(MtuResult(mtu=1399)) == 0

    def test_probe_failure_is_zero(self) -> None:
        assert health.score_mtu(MtuResult()) == 0

    def test_verified_flag_does_not_change_score(self) -> None:
        assert health.score_mtu(MtuResult(mtu=1492, payload=1464, verified=False)) == 8


# ===========================================================================
# 其余维度边界（保持旧档位）
# ===========================================================================
class TestScoreWan:
    def test_fast_no_loss_is_full(self) -> None:
        assert health.score_wan(stat(avg_ms=26, loss_pct=0)) == 25

    def test_loss_bonus_tiers(self) -> None:
        assert health.score_wan(stat(avg_ms=26, loss_pct=2)) == 20  # 15 + 5
        assert health.score_wan(stat(avg_ms=26, loss_pct=3)) == 15  # 15 + 0

    def test_delay_bounds(self) -> None:
        assert health.score_wan(stat(avg_ms=30, loss_pct=0)) == 25
        assert health.score_wan(stat(avg_ms=150, loss_pct=0)) == 10  # 延迟 0 + 无丢包 10
        assert health.score_wan(stat(avg_ms=None, loss_pct=100)) == 0


class TestScoreDns:
    def test_no_measurement_is_zero(self) -> None:
        assert health.score_dns([]) == 0
        assert health.score_dns([None, None]) == 0

    def test_bounds(self) -> None:
        assert health.score_dns([30.0]) == 20
        assert health.score_dns([200.0]) == 0

    def test_average_skips_failed_servers(self) -> None:
        # 只统计成功项：(10+90)/2 = 50 → (200-50)/170*20 = 17.6 → 18
        assert health.score_dns([10.0, None, 90.0]) == 18

    def test_dns_average_helper(self) -> None:
        assert health.dns_average([]) is None
        assert health.dns_average([None]) is None
        assert health.dns_average([10.0, 20.0]) == 15.0


class TestScoreHttp:
    def test_bounds_and_none(self) -> None:
        assert health.score_http(149) == 20
        assert health.score_http(150) == 20
        assert health.score_http(1000) == 0
        assert health.score_http(None) == 0

    def test_midpoint(self) -> None:
        # (1000-575)/850*20 = 10
        assert health.score_http(575) == 10


class TestTotalAndGrade:
    def test_weights_unchanged_from_legacy(self) -> None:
        # 旧版权重 15/25/20/20/10，合计 90，总分归一化到 100
        assert (health.WEIGHT_GATEWAY, health.WEIGHT_WAN, health.WEIGHT_DNS) == (15, 25, 20)
        assert (health.WEIGHT_HTTP, health.WEIGHT_MTU) == (20, 10)

    def test_all_full_is_100(self) -> None:
        assert health.total_score(_items((15, 15), (25, 25), (20, 20), (20, 20), (10, 10))) == 100

    def test_all_zero_is_0(self) -> None:
        assert health.total_score(_items((0, 15), (0, 25), (0, 20), (0, 20), (0, 10))) == 0

    def test_empty_is_zero(self) -> None:
        assert health.total_score([]) == 0

    def test_normalization_matches_legacy_math(self) -> None:
        # 8+25+20+20+8 = 81；81/90*100 = 90
        assert health.total_score(_items((8, 15), (25, 25), (20, 20), (20, 20), (8, 10))) == 90

    @pytest.mark.parametrize(
        ("total", "expected"),
        [
            (100, "优"),
            (85, "优"),
            (84, "良"),
            (70, "良"),
            (69, "中"),
            (50, "中"),
            (49, "差"),
            (0, "差"),
        ],
    )
    def test_grade_boundaries(self, total: int, expected: str) -> None:
        assert health.grade(total) == expected


# ===========================================================================
# 渲染（纯函数）
# ===========================================================================
class TestDescribeGateway:
    def test_unreachable(self) -> None:
        detail, advice = health.describe_gateway(stat(avg_ms=None, loss_pct=100))
        assert detail == "网关不可达"
        assert any("网关不可达" in a for a in advice)

    def test_normal(self) -> None:
        detail, advice = health.describe_gateway(stat(avg_ms=9.6, loss_pct=0.0))
        assert detail == "网关 9.6 ms / 丢包 0.0%"
        assert advice == []

    def test_high_latency_and_loss_get_advice(self) -> None:
        detail, advice = health.describe_gateway(stat(avg_ms=20.0, loss_pct=10.0))
        assert "20.0" in detail
        assert any("延迟偏高" in a for a in advice)
        assert any("丢包" in a for a in advice)


class TestDescribeWan:
    def test_unreachable(self) -> None:
        detail, advice = health.describe_wan(stat(avg_ms=None, loss_pct=100))
        assert detail == "外网不可达"
        assert advice

    def test_normal(self) -> None:
        detail, advice = health.describe_wan(stat(avg_ms=26.4, loss_pct=0.0))
        assert detail == "百度 26.4 ms / 丢包 0.0%"
        assert advice == []

    def test_slow_and_lossy_get_advice(self) -> None:
        _, advice = health.describe_wan(stat(avg_ms=100.0, loss_pct=1.0))
        assert any("延迟偏高" in a for a in advice)
        assert any("丢包" in a for a in advice)


class TestDescribeDns:
    def test_no_real_config_does_not_fake_a_server(self) -> None:
        # D3：旧实现拿 223.5.5.5 顶替；新实现如实报「未获取到 DNS 配置」
        detail, advice = health.describe_dns([], [])
        assert detail == "未获取到 DNS 配置"
        assert any("fix dns" in a for a in advice)

    def test_all_queries_failed(self) -> None:
        detail, advice = health.describe_dns([None, None], ["114.114.114.114", "192.0.2.1"])
        assert detail == "DNS 解析失败"
        assert advice

    def test_normal_and_slow(self) -> None:
        detail, advice = health.describe_dns([22.0], ["114.114.114.114"])
        assert detail == "DNS 解析 22 ms"
        assert advice == []
        _, slow_advice = health.describe_dns([150.0], ["114.114.114.114"])
        assert any("偏慢" in a for a in slow_advice)


class TestDescribeHttp:
    def test_failure(self) -> None:
        detail, advice = health.describe_http(None)
        assert detail == "HTTP 连接失败"
        assert advice

    def test_normal_and_slow(self) -> None:
        detail, advice = health.describe_http(30.0)
        assert detail == "百度 HTTPS 30.0 ms"
        assert advice == []
        _, slow_advice = health.describe_http(600.0)
        assert any("响应慢" in a for a in slow_advice)


class TestDescribeMtu:
    def test_pppoe_marks_dialup_line_and_mss_advice(self) -> None:
        detail, advice = health.describe_mtu(MtuResult(mtu=1492, payload=1464, verified=True))
        assert "1492" in detail and "PPPoE" in detail
        assert any("MSS" in a for a in advice)

    def test_unverified_probe_is_flagged(self) -> None:
        detail, _ = health.describe_mtu(MtuResult(mtu=1492, payload=1464, verified=False))
        assert "探测未经确认" in detail

    def test_failed_probe(self) -> None:
        detail, advice = health.describe_mtu(MtuResult())
        assert "未知" in detail
        assert advice

    def test_standard(self) -> None:
        detail, advice = health.describe_mtu(MtuResult(mtu=1500, payload=1472, verified=True))
        assert "标准以太网" in detail
        assert advice == []

    def test_low_bands(self) -> None:
        assert "低于标准 1500" in health.describe_mtu(MtuResult(mtu=1495))[0]
        assert "偏低" in health.describe_mtu(MtuResult(mtu=1450))[0]
        assert "严重偏低" in health.describe_mtu(MtuResult(mtu=1300))[0]


class TestRenderReport:
    def test_full_layout(self) -> None:
        items = [
            ItemScore("网关", 15, 15, "网关 9.6 ms / 丢包 0.0%"),
            ItemScore("MTU", 8, 10, "MTU 1492（PPPoE 拨号线路）"),
        ]
        text = "\n".join(health.render_report(items, []))
        assert "== 健康评分 ==" in text
        assert "15/15" in text and "8/10" in text
        assert "█" in text and "░" in text
        assert "网关 9.6 ms / 丢包 0.0%" in text
        assert "MTU 1492（PPPoE 拨号线路）" in text
        # (15+8)/(15+10) = 92%
        assert "92 分" in text
        assert "评级" in text and "优" in text
        assert "一切正常" in text
        assert "上次评分" not in text

    def test_advice_block_and_trend_down(self) -> None:
        items = [ItemScore("MTU", 8, 10, "d")]
        text = "\n".join(
            health.render_report(items, ["MTU 1492 为 PPPoE 拨号线路 — 测试建议"], prev_score=83)
        )
        assert "优化建议:" in text
        assert "·" in text and "测试建议" in text
        # 8/10 → 80 分；80-83 = -3
        assert "上次评分 83 分  本次 80 分" in text
        assert "↓ -3" in text

    def test_trend_flat(self) -> None:
        text = "\n".join(health.render_report([ItemScore("HTTP", 20, 20, "d")], [], prev_score=100))
        assert "→ 持平" in text

    def test_trend_up(self) -> None:
        text = "\n".join(health.render_report([ItemScore("HTTP", 10, 20, "d")], [], prev_score=10))
        assert "↑ +40" in text


# ===========================================================================
# 编排辅助函数
# ===========================================================================
class TestDnsServerSelection:
    def test_prefers_primary_interface_and_skips_ipv6(self, monkeypatch) -> None:
        configs = [
            DnsConfig(
                interface="以太网",
                index=2,
                servers=["114.114.114.114", "fe80::1%1"],
                source="static",
            ),
            DnsConfig(interface="Example VPN", index=5, servers=["198.51.100.1"], source="static"),
        ]
        monkeypatch.setattr(probes, "dns_config", lambda run=None: configs)
        monkeypatch.setattr(
            probes, "primary_interfaces", lambda run=None: [Interface("以太网", 2, 1500, True)]
        )

        # IPv6 过不了 AF_INET 的 dns_query，必须剔除；虚拟网卡的 DNS 不能顶上来
        assert health._dns_servers_to_test(None) == ["114.114.114.114"]

    def test_falls_back_to_all_configs_and_caps_at_two(self, monkeypatch) -> None:
        configs = [DnsConfig(interface="WLAN", index=3, servers=["8.8.8.8", "1.1.1.1", "9.9.9.9"])]
        monkeypatch.setattr(probes, "dns_config", lambda run=None: configs)
        monkeypatch.setattr(probes, "primary_interfaces", lambda run=None: [])

        assert health._dns_servers_to_test(None) == ["8.8.8.8", "1.1.1.1"]


class TestLastHealthScore:
    def test_returns_most_recent_health_score(self) -> None:
        state.HISTORY_FILE.write_text(
            json.dumps(
                {
                    "entries": [
                        {"cmd": "status", "score": 5},
                        {"cmd": "health", "score": 77},
                        {"cmd": "health", "ts": "无 score 的条目"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        assert health._last_health_score() == 77

    def test_none_when_history_missing_or_broken(self) -> None:
        assert health._last_health_score() is None
        state.HISTORY_FILE.write_text("not json", encoding="utf-8")
        assert health._last_health_score() is None


# ===========================================================================
# 端到端：fake_run + capsys（绝不真实执行命令）
# ===========================================================================
def _mtu_aware(base, limit: int = _MTU_LIMIT):
    """给 conftest 的 fake_run 补上「按 -l 值分支」的能力。

    fake_run 只支持固定前缀匹配，而 MTU 探测的返回值取决于 payload 数值。
    样本全部真实抓取：payload<=limit 通，否则报「需要拆分数据包但是设置 DF」。
    """
    calls: list[list[str]] = []

    def run(argv, timeout=30.0, **kwargs):
        argv = list(argv)
        calls.append(argv)
        if argv[:2] == ["ping", "-f"]:
            payload = int(argv[argv.index("-l") + 1])
            if payload <= limit:
                out = fixture_text("ping_df_ok").replace("1464", str(payload))
                return CmdResult(argv=argv, code=0, out=out)
            out = fixture_text("ping_df_fail").replace("1472", str(payload))
            return CmdResult(argv=argv, code=1, out=out)
        return base(argv, timeout)

    run.calls = calls  # type: ignore[attr-defined]
    return run


_PING_OK = {
    ("ping", "-n", "4", "-w", "1000", "192.0.2.1"): (fixture_text("ping_ok"), 0),
    ("ping", "-n", "4", "-w", "1000", "www.baidu.com"): (fixture_text("ping_ok"), 0),
}


def _health_run(fake_run, *, route_code: int = 0, mtu_limit: int = _MTU_LIMIT, ping_table=None):
    table = {
        ("route", "print"): (
            fixture_text("route_print_default") if route_code == 0 else "",
            route_code,
        ),
        ("ipconfig", "/all"): (fixture_text("ipconfig_all"), 0),
        ("netsh", "interface", "ipv4", "show", "interfaces"): fixture_text("netsh_interfaces"),
        ("netsh", "interface", "ipv4", "show", "dnsservers"): fixture_text("netsh_dnsservers"),
    }
    if ping_table:
        table.update(ping_table)
    return _mtu_aware(fake_run(table), limit=mtu_limit)


def test_cmd_health_end_to_end_scores_pppoe_link(fake_run, monkeypatch, capsys) -> None:
    monkeypatch.setattr(probes, "dns_query", lambda server, host, timeout=3.0: 22.0)
    monkeypatch.setattr(probes, "http_ttfb", lambda host, port=443, timeout=5.0: 30.0)
    run = _health_run(fake_run, ping_table=_PING_OK)

    health.cmd_health(run=run)
    out = capsys.readouterr().out

    for label in ("网关", "外网", "DNS", "HTTP", "MTU"):
        assert label in out
    # 网关 ping 的是真实默认路由 192.0.2.1，不是 Example VPN 的 198.51.100.1（D1 接线）
    assert any(call[0] == "ping" and call[-1] == "192.0.2.1" for call in run.calls)
    assert all("198.51.100.1" not in call for call in run.calls)
    # D6：1492（PPPoE）不再满分，且如实标注
    assert "MTU 1492（PPPoE 拨号线路）" in out
    assert "8/10" in out
    assert "10/10" not in out
    # 归一化：网关 8 + 外网 25 + DNS 20 + HTTP 20 + MTU 8 = 81；81/90*100 = 90
    assert "90 分" in out
    entries = state.hist_load()["entries"]
    assert entries[-1]["cmd"] == "health"
    assert entries[-1]["score"] == 90
    assert len(entries[-1]["detail"]) == 5


def test_cmd_health_end_to_end_all_failures(fake_run, monkeypatch, capsys) -> None:
    monkeypatch.setattr(probes, "dns_query", lambda server, host, timeout=3.0: None)
    monkeypatch.setattr(probes, "http_ttfb", lambda host, port=443, timeout=5.0: None)
    run = _health_run(
        fake_run,
        route_code=1,  # route 里没有默认路由
        mtu_limit=0,  # 连 68 字节都 DF 失败 → 测不到 MTU
        ping_table={
            ("ping", "-n", "4", "-w", "1000", "www.baidu.com"): (
                fixture_text("ping_loss100"),
                1,
            )
        },
    )

    health.cmd_health(run=run)
    out = capsys.readouterr().out

    assert "网关不可达" in out
    assert "外网不可达" in out
    assert "DNS 解析失败" in out
    assert "HTTP 连接失败" in out
    assert "MTU 未知（探测失败）" in out
    assert "0 分" in out
    assert "差" in out
    assert "优化建议:" in out
    # 没有默认路由就不该瞎猜一个网关去 ping
    assert not any(call[0] == "ping" and "192.0.2.1" in call for call in run.calls)


def test_cmd_health_trend_reads_history_before_writing(fake_run, monkeypatch, capsys) -> None:
    state.HISTORY_FILE.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "cmd": "health",
                        "ts": "2026-08-19 23:17:55",
                        "score": 83,
                        "detail": ["网关不可达"],
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(probes, "dns_query", lambda server, host, timeout=3.0: 22.0)
    monkeypatch.setattr(probes, "http_ttfb", lambda host, port=443, timeout=5.0: 30.0)
    run = _health_run(fake_run, ping_table=_PING_OK)

    health.cmd_health(run=run)
    out = capsys.readouterr().out

    # 必须「先 hist_load 再 hist_add」：prev=83，若顺序反了这里会显示 90
    assert "上次评分 83 分" in out
    assert "本次 90 分" in out
    assert "↑ +7" in out
    assert [e["score"] for e in state.hist_load()["entries"]] == [83, 90]


def test_cmd_health_queries_real_configured_dns_only(fake_run, monkeypatch, capsys) -> None:
    tested: list[str] = []

    def fake_dns(server, host, timeout=3.0):
        tested.append(server)
        return 20.0

    monkeypatch.setattr(probes, "dns_query", fake_dns)
    monkeypatch.setattr(probes, "http_ttfb", lambda host, port=443, timeout=5.0: 30.0)
    run = _health_run(fake_run, ping_table=_PING_OK)

    health.cmd_health(run=run)
    out = capsys.readouterr().out

    assert tested == ["114.114.114.114", "192.0.2.1"]  # 本机以太网真实静态 DNS
    assert "223.5.5.5" not in tested  # 旧实现拿它顶替（D3），新实现绝不测它
    assert "DNS 解析 20 ms" in out
