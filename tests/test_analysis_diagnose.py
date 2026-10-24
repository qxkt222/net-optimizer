# -*- coding: utf-8 -*-
"""netopt.analysis.diagnose 测试：归因链、优先级、阈值边界与纯函数性质。

约定（BRIEF §8）：本模块不碰 IO，测试里没有 runner / monkeypatch。断言的
阈值取自 :class:`~netopt.domain.policy.Policy` 本身，边界值显式写死，避免
「拿被测函数的常量反过来当预期」。
"""

from __future__ import annotations

import inspect
from collections.abc import Sequence

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

import netopt.analysis.diagnose as diagnose_module
from netopt.analysis.diagnose import (
    TCP_RETRANSMIT_WARN,
    ConnectivitySnapshot,
    diagnose,
)
from netopt.domain import Band, Finding, FindingCode, LossPolicy, Policy, Severity
from netopt.models import MtuResult, PingStat

POLICY = Policy.default()


def stat(avg_ms: float | None = 26.0, loss_pct: float = 0.0, target: str = "test") -> PingStat:
    """构造一次 ping 结果（``avg_ms`` 为 None 表示一个回复都没收到）。"""
    return PingStat(
        target=target,
        avg_ms=avg_ms,
        loss_pct=loss_pct,
        replies=0 if avg_ms is None else 4,
    )


def snapshot(**overrides: object) -> ConnectivitySnapshot:
    """全部指标正常的快照；用 overrides 替换单个维度。"""
    kwargs: dict[str, object] = {
        "gateway": stat(1.0, 0.0, "192.0.2.1"),
        "wan": stat(26.0, 0.0, "223.5.5.5"),
        "dns_avg_ms": 20.0,
        "dns_servers": ["223.5.5.5"],
        "http_ttfb_ms": 30.0,
        "mtu": MtuResult(mtu=1500, verified=True),
        "tcp_retransmits": 0,
    }
    kwargs.update(overrides)
    return ConnectivitySnapshot(**kwargs)  # type: ignore[arg-type]


def _codes(findings: Sequence[Finding]) -> list[str]:
    return [finding.code for finding in findings]


def _only(findings: Sequence[Finding], code: FindingCode) -> Finding:
    matched = [finding for finding in findings if finding.code == code]
    assert len(matched) == 1, f"期望恰好一条 {code}，实际 {_codes(findings)}"
    return matched[0]


# ===========================================================================
# 归因链 1：本地链路
# ===========================================================================
class TestLocalLink:
    def test_missing_gateway_is_critical(self) -> None:
        finding = _only(diagnose(snapshot(gateway=None)), FindingCode.DIAG_LOCAL_LINK)
        assert finding.severity is Severity.critical
        assert "默认网关" in finding.detail
        assert finding.advice

    def test_unreachable_gateway_is_critical(self) -> None:
        finding = _only(
            diagnose(snapshot(gateway=stat(None, 100.0, "192.0.2.1"))),
            FindingCode.DIAG_LOCAL_LINK,
        )
        assert finding.severity is Severity.critical
        # detail 必须引用具体测量值：目标地址与丢包率
        assert "192.0.2.1" in finding.detail
        assert "100.0%" in finding.detail


# ===========================================================================
# 归因链 2：本地接入段（WiFi / 网线 / 路由器）
# ===========================================================================
class TestAccessNetwork:
    def test_gateway_loss_warn(self) -> None:
        finding = _only(
            diagnose(snapshot(gateway=stat(1.0, 10.0))),
            FindingCode.DIAG_ACCESS_NETWORK,
        )
        assert finding.severity is Severity.warn
        assert "10.0%" in finding.detail

    def test_gateway_major_loss_is_critical(self) -> None:
        finding = _only(
            diagnose(snapshot(gateway=stat(1.0, 60.0))),
            FindingCode.DIAG_ACCESS_NETWORK,
        )
        assert finding.severity is Severity.critical

    def test_gateway_latency_alone_is_not_attributed_here(self) -> None:
        # 延迟只影响体验，不改变「问题在哪一段」；归因链只按丢包切段。
        assert diagnose(snapshot(gateway=stat(200.0, 0.0))) == []


# ===========================================================================
# 归因链 3：运营商 / 骨干
# ===========================================================================
class TestIspBackbone:
    def test_wan_unreachable_is_critical(self) -> None:
        finding = _only(
            diagnose(snapshot(wan=stat(None, 100.0))),
            FindingCode.DIAG_ISP_BACKBONE,
        )
        assert finding.severity is Severity.critical
        assert "100.0%" in finding.detail

    def test_wan_loss_warn(self) -> None:
        finding = _only(
            diagnose(snapshot(wan=stat(26.0, 10.0))),
            FindingCode.DIAG_ISP_BACKBONE,
        )
        assert finding.severity is Severity.warn
        assert "10.0%" in finding.detail

    def test_wan_major_loss_is_critical(self) -> None:
        finding = _only(
            diagnose(snapshot(wan=stat(26.0, 60.0))),
            FindingCode.DIAG_ISP_BACKBONE,
        )
        assert finding.severity is Severity.critical


# ===========================================================================
# 归因链 4：DNS
# ===========================================================================
class TestDns:
    def test_all_queries_failed_is_critical(self) -> None:
        finding = _only(
            diagnose(snapshot(dns_avg_ms=None, dns_servers=["192.0.2.1", "192.0.2.2"])),
            FindingCode.DIAG_DNS,
        )
        assert finding.severity is Severity.critical
        assert "192.0.2.1" in finding.detail
        assert "2 个" in finding.detail

    def test_slow_dns_is_warn(self) -> None:
        finding = _only(
            diagnose(snapshot(dns_avg_ms=150.0)),
            FindingCode.DIAG_DNS,
        )
        assert finding.severity is Severity.warn
        assert "150" in finding.detail

    def test_empty_server_list_skips_dns_attribution(self) -> None:
        # 没有配置 DNS 就没有可测对象，不能把「没配置」误报成「DNS 故障」。
        assert diagnose(snapshot(dns_servers=[], dns_avg_ms=None)) == []


# ===========================================================================
# 归因链 5：应用层
# ===========================================================================
class TestAppLayer:
    def test_http_failure_is_warn(self) -> None:
        finding = _only(
            diagnose(snapshot(http_ttfb_ms=None)),
            FindingCode.DIAG_APP_LAYER,
        )
        assert finding.severity is Severity.warn
        # detail 必须给出前三段的实测值，说明不是链路的问题
        assert "1.0 ms" in finding.detail
        assert "26.0 ms" in finding.detail
        assert "20 ms" in finding.detail

    def test_http_slow_is_warn(self) -> None:
        finding = _only(
            diagnose(snapshot(http_ttfb_ms=600.0)),
            FindingCode.DIAG_APP_LAYER,
        )
        assert finding.severity is Severity.warn
        assert "600" in finding.detail


# ===========================================================================
# 归因链 6：线路质量 / 驱动（TCP 重传）
# ===========================================================================
class TestTcpRetransmit:
    def test_high_retransmits_is_warn(self) -> None:
        finding = _only(
            diagnose(snapshot(tcp_retransmits=TCP_RETRANSMIT_WARN + 1)),
            FindingCode.DIAG_TCP_RETRANSMIT,
        )
        assert finding.severity is Severity.warn
        assert str(TCP_RETRANSMIT_WARN + 1) in finding.detail

    def test_at_threshold_is_still_ok(self) -> None:
        # 严格大于才报：等于阈值视为可接受
        assert diagnose(snapshot(tcp_retransmits=TCP_RETRANSMIT_WARN)) == []

    def test_missing_retransmits_is_ok(self) -> None:
        assert diagnose(snapshot(tcp_retransmits=None)) == []


# ===========================================================================
# 同一根因只报一条
# ===========================================================================
class TestSingleRootCause:
    def test_gateway_unreachable_suppresses_everything_downstream(self) -> None:
        findings = diagnose(
            snapshot(
                gateway=stat(None, 100.0),
                wan=stat(None, 100.0),
                dns_avg_ms=None,
                http_ttfb_ms=None,
                tcp_retransmits=99,
            )
        )
        assert _codes(findings) == [FindingCode.DIAG_LOCAL_LINK.value]

    def test_access_loss_suppresses_wan_and_above(self) -> None:
        findings = diagnose(
            snapshot(
                gateway=stat(1.0, 10.0),
                wan=stat(None, 100.0),
                dns_avg_ms=None,
                http_ttfb_ms=None,
            )
        )
        assert _codes(findings) == [FindingCode.DIAG_ACCESS_NETWORK.value]

    def test_isp_suppresses_dns_and_app(self) -> None:
        findings = diagnose(
            snapshot(
                wan=stat(None, 100.0),
                dns_avg_ms=None,
                http_ttfb_ms=None,
                tcp_retransmits=99,
            )
        )
        assert _codes(findings) == [FindingCode.DIAG_ISP_BACKBONE.value]

    def test_dns_suppresses_app_and_tcp(self) -> None:
        findings = diagnose(snapshot(dns_avg_ms=None, http_ttfb_ms=None, tcp_retransmits=99))
        assert _codes(findings) == [FindingCode.DIAG_DNS.value]

    def test_app_suppresses_tcp(self) -> None:
        findings = diagnose(snapshot(http_ttfb_ms=None, tcp_retransmits=99))
        assert _codes(findings) == [FindingCode.DIAG_APP_LAYER.value]


# ===========================================================================
# 阈值边界：全部取自 Policy
# ===========================================================================
class TestThresholdBoundaries:
    def test_gateway_loss_equal_tolerate_is_ok(self) -> None:
        assert diagnose(snapshot(gateway=stat(1.0, POLICY.loss.tolerate))) == []

    def test_gateway_loss_equal_unusable_is_critical(self) -> None:
        finding = _only(
            diagnose(snapshot(gateway=stat(1.0, POLICY.loss.unusable))),
            FindingCode.DIAG_ACCESS_NETWORK,
        )
        assert finding.severity is Severity.critical

    def test_wan_loss_equal_tolerate_is_ok(self) -> None:
        assert diagnose(snapshot(wan=stat(26.0, POLICY.loss.tolerate))) == []

    def test_wan_loss_equal_unusable_is_critical(self) -> None:
        finding = _only(
            diagnose(snapshot(wan=stat(26.0, POLICY.loss.unusable))),
            FindingCode.DIAG_ISP_BACKBONE,
        )
        assert finding.severity is Severity.critical

    def test_dns_equal_warn_is_ok(self) -> None:
        assert diagnose(snapshot(dns_avg_ms=POLICY.dns.warn)) == []

    def test_http_equal_warn_is_ok(self) -> None:
        assert diagnose(snapshot(http_ttfb_ms=POLICY.http_ttfb.warn)) == []

    @pytest.mark.parametrize("tcp", [0, 1, 2, TCP_RETRANSMIT_WARN])
    def test_tcp_below_or_at_threshold_is_ok(self, tcp: int) -> None:
        assert diagnose(snapshot(tcp_retransmits=tcp)) == []


# ===========================================================================
# 自定义 Policy：阈值生效，权重与归因无关
# ===========================================================================
class TestCustomPolicy:
    def test_custom_loss_thresholds(self) -> None:
        pol = Policy(loss=LossPolicy(tolerate=5, unusable=80))
        assert diagnose(snapshot(gateway=stat(1.0, 5.0)), pol) == []
        warn = _only(
            diagnose(snapshot(gateway=stat(1.0, 5.1)), pol),
            FindingCode.DIAG_ACCESS_NETWORK,
        )
        assert warn.severity is Severity.warn
        critical = _only(
            diagnose(snapshot(gateway=stat(1.0, 80.0)), pol),
            FindingCode.DIAG_ACCESS_NETWORK,
        )
        assert critical.severity is Severity.critical

    def test_custom_dns_band(self) -> None:
        pol = Policy(dns=Band(good=10, warn=50, poor=100))
        assert diagnose(snapshot(dns_avg_ms=50.0), pol) == []
        finding = _only(
            diagnose(snapshot(dns_avg_ms=60.0), pol),
            FindingCode.DIAG_DNS,
        )
        assert "50 ms" in finding.detail

    def test_custom_http_band(self) -> None:
        pol = Policy(http_ttfb=Band(good=50, warn=200, poor=400))
        assert diagnose(snapshot(http_ttfb_ms=200.0), pol) == []
        finding = _only(
            diagnose(snapshot(http_ttfb_ms=300.0), pol),
            FindingCode.DIAG_APP_LAYER,
        )
        assert "200 ms" in finding.detail

    def test_weights_do_not_change_attribution(self) -> None:
        # 权重只影响评分；归因只看阈值，改权重不应改变结论。
        heavy = Policy(weights={"gateway": 30, "wan": 40, "dns": 10, "http": 10, "mtu": 10})
        assert diagnose(snapshot()) == diagnose(snapshot(), heavy)

    def test_explicit_default_policy_matches_none(self) -> None:
        broken = snapshot(gateway=stat(None, 100.0))
        assert diagnose(broken) == diagnose(broken, Policy.default())


# ===========================================================================
# 全正常 / 结论形状 / 纯函数性质
# ===========================================================================
class TestHealthyAndShape:
    def test_all_normal_returns_empty_list(self) -> None:
        assert diagnose(snapshot()) == []

    def test_at_most_one_finding(self) -> None:
        scenarios = [
            snapshot(gateway=None),
            snapshot(gateway=stat(1.0, 10.0)),
            snapshot(wan=stat(None, 100.0)),
            snapshot(dns_avg_ms=None),
            snapshot(http_ttfb_ms=None),
            snapshot(tcp_retransmits=99),
        ]
        for scenario in scenarios:
            findings = diagnose(scenario)
            assert len(findings) <= 1

    def test_every_finding_has_measurements_and_actionable_advice(self) -> None:
        scenarios = [
            snapshot(gateway=None),
            snapshot(gateway=stat(None, 100.0)),
            snapshot(gateway=stat(1.0, 10.0)),
            snapshot(wan=stat(None, 100.0)),
            snapshot(wan=stat(26.0, 10.0)),
            snapshot(dns_avg_ms=None),
            snapshot(dns_avg_ms=150.0),
            snapshot(http_ttfb_ms=None),
            snapshot(http_ttfb_ms=600.0),
            snapshot(tcp_retransmits=99),
        ]
        valid_codes = {code.value for code in FindingCode}
        for scenario in scenarios:
            findings = diagnose(scenario)
            assert len(findings) == 1
            for finding in findings:
                assert finding.code in valid_codes
                assert finding.detail.strip()
                assert finding.advice
                assert all(advice.strip() for advice in finding.advice)


class TestPurity:
    def test_deterministic_and_silent(self, capsys: pytest.CaptureFixture[str]) -> None:
        scenario = snapshot(gateway=stat(None, 100.0), tcp_retransmits=99)
        assert diagnose(scenario) == diagnose(scenario)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_module_has_no_io_dependencies(self) -> None:
        source = inspect.getsource(diagnose_module)
        for banned in ("import subprocess", "import socket", "httpx", "open(", "print("):
            assert banned not in source


# ===========================================================================
# hypothesis：外网丢包增加时，运营商归因一定出现（网关正常）
# ===========================================================================
_LOSS = st.floats(min_value=0, max_value=100, allow_nan=False, allow_infinity=False)


class TestWanLossProperty:
    @given(loss=_LOSS)
    def test_any_wan_loss_above_tolerate_is_isp(self, loss: float) -> None:
        assume(loss > POLICY.loss.tolerate)
        findings = diagnose(snapshot(wan=stat(26.0, loss)))
        assert _codes(findings) == [FindingCode.DIAG_ISP_BACKBONE.value]

    @given(a=_LOSS, b=_LOSS)
    def test_more_wan_loss_never_hides_isp(self, a: float, b: float) -> None:
        low, high = min(a, b), max(a, b)
        assume(low > POLICY.loss.tolerate)
        code = FindingCode.DIAG_ISP_BACKBONE.value
        assert code in _codes(diagnose(snapshot(wan=stat(26.0, low))))
        assert code in _codes(diagnose(snapshot(wan=stat(26.0, high))))
