# -*- coding: utf-8 -*-
"""HTTP 探测测试 —— 纯函数 + 假 ``httpx.Client``，绝不访问外网。

httpx 0.28.1 / httpcore 1.0.9 的事件名由本机回环实测确认（见
``netopt/probes_http.py`` 模块 docstring），这里不再猜字段。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, ClassVar

import httpx
import pytest

from netopt import probes_http
from netopt.domain.codes import ProbeErrorCode
from netopt.probes import ProbeContext

#: 假 trace：connect 10ms、TLS 40ms、发送完成 → 收到响应头 98ms。
_TRACE: list[tuple[float, str]] = [
    (0.000, "connection.connect_tcp.started"),
    (0.010, "connection.connect_tcp.complete"),
    (0.012, "connection.start_tls.started"),
    (0.052, "connection.start_tls.complete"),
    (0.053, "http11.send_request_headers.started"),
    (0.055, "http11.send_request_headers.complete"),
    (0.100, "http11.receive_response_headers.started"),
    (0.153, "http11.receive_response_headers.complete"),
]


class _FakeResponse:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code


class _FakeClient:
    """记录构造参数与请求参数，并按预设 trace 回调假事件。"""

    captured: ClassVar[dict[str, Any]] = {}
    last: ClassVar[dict[str, Any]] = {}
    events: ClassVar[list[tuple[float, str]]] = _TRACE
    status_code: ClassVar[int] = 204

    def __init__(self, **kwargs: Any) -> None:
        type(self).captured = kwargs

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> _FakeResponse:
        type(self).last = {"url": url, "headers": headers}
        trace = (extensions or {}).get("trace")
        if trace is not None:
            for _stamp, name in self.events:
                trace(name, {})
        return _FakeResponse(self.status_code)


class _RaisingClient:
    """请求时抛指定异常，用于验证错误映射。"""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def __enter__(self) -> _RaisingClient:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, *args: object, **kwargs: object) -> _FakeResponse:
        raise self._exc


# ===========================================================================
# 纯函数：trace → 四段
# ===========================================================================
def test_phases_from_trace_computes_four_segments() -> None:
    """四段耗时按事件时间戳精确折算。"""
    phases = probes_http._phases_from_trace(_TRACE, total_ms=250.0)

    assert phases.connect_ms == pytest.approx(10.0)
    assert phases.tls_ms == pytest.approx(40.0)
    assert phases.ttfb_ms == pytest.approx(98.0)
    assert phases.total_ms == pytest.approx(250.0)


def test_phases_from_trace_without_tls() -> None:
    """明文 HTTP 没有 start_tls，TLS 段必须是 None 而不是 0。"""
    events = [
        (0.000, "connection.connect_tcp.started"),
        (0.020, "connection.connect_tcp.complete"),
        (0.021, "http11.send_request_headers.started"),
        (0.023, "http11.send_request_headers.complete"),
        (0.043, "http11.receive_response_headers.complete"),
    ]

    phases = probes_http._phases_from_trace(events)

    assert phases.connect_ms == pytest.approx(20.0)
    assert phases.tls_ms is None
    assert phases.ttfb_ms == pytest.approx(20.0)
    assert phases.total_ms is None


def test_phases_from_trace_empty() -> None:
    """没有 trace 时四段全空，调用方只能退回 perf_counter 的总耗时。"""
    phases = probes_http._phases_from_trace([])

    assert phases.connect_ms is None
    assert phases.tls_ms is None
    assert phases.ttfb_ms is None
    assert phases.total_ms is None


def test_span_rejects_backwards_timestamps() -> None:
    """时间倒流的坏数据不能算出负耗时。"""
    events = [
        (0.050, "connection.connect_tcp.started"),
        (0.010, "connection.connect_tcp.complete"),
    ]

    phases = probes_http._phases_from_trace(events)

    assert phases.connect_ms is None


# ===========================================================================
# measure：成功路径（假 Client）
# ===========================================================================
def _deterministic_tracer(
    events: list[tuple[float, str]],
) -> Callable[[str, dict[str, object]], None]:
    """用 ``_TRACE`` 里的固定时间戳替换真实时钟，便于断言精确耗时。"""
    stamps = iter(stamp for stamp, _name in _TRACE)

    def _trace(name: str, _info: dict[str, object]) -> None:
        events.append((next(stamps), name))

    return _trace


def test_measure_extracts_segments_and_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """trace 可用时四段齐全，并按约定构造 client 与请求。"""
    monkeypatch.setattr(probes_http.httpx, "Client", _FakeClient)
    monkeypatch.setattr(probes_http, "_make_tracer", _deterministic_tracer)

    result = probes_http.measure("example.test", port=8443, timeout=2.0)

    assert result.status == 204
    assert result.error is None
    assert result.error_code is None
    assert result.connect_ms == pytest.approx(10.0)
    assert result.tls_ms == pytest.approx(40.0)
    assert result.ttfb_ms == pytest.approx(98.0)
    assert result.total_ms is not None

    assert _FakeClient.captured["follow_redirects"] is False
    assert _FakeClient.captured["timeout"] == 2.0
    assert _FakeClient.captured["verify"] is True
    assert _FakeClient.last["headers"] == {"Connection": "close"}
    assert _FakeClient.last["url"] == "https://example.test:8443/"


def test_measure_without_trace_keeps_only_total(monkeypatch: pytest.MonkeyPatch) -> None:
    """取不到 trace 时只留 perf_counter 的总耗时，其余不得编造。"""
    no_trace = type("_NoTraceClient", (_FakeClient,), {"events": []})
    monkeypatch.setattr(probes_http.httpx, "Client", no_trace)

    result = probes_http.measure("example.test")

    assert result.status == 204
    assert result.connect_ms is None
    assert result.tls_ms is None
    assert result.ttfb_ms is None
    assert result.total_ms is not None


def test_measure_brackets_ipv6_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    """IPv6 字面量必须加方括号，否则 URL 解析会错。"""
    monkeypatch.setattr(probes_http.httpx, "Client", _FakeClient)

    probes_http.measure("::1", port=443)

    assert _FakeClient.last["url"] == "https://[::1]:443/"


# ===========================================================================
# measure：失败路径
# ===========================================================================
@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (httpx.ConnectTimeout("连接超时"), ProbeErrorCode.TIMEOUT.value),
        (httpx.ConnectError("连接被拒绝"), ProbeErrorCode.NETWORK.value),
        (httpx.ReadError("读取失败"), ProbeErrorCode.NETWORK.value),
        (ValueError("坏配置"), ProbeErrorCode.UNAVAILABLE.value),
    ],
)
def test_measure_maps_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    exc: BaseException,
    code: str,
) -> None:
    """任何异常都转成带 code 的失败结果，并写入 ProbeContext。"""
    monkeypatch.setattr(probes_http.httpx, "Client", lambda **kwargs: _RaisingClient(exc))
    ctx = ProbeContext.with_budget(5.0)

    result = probes_http.measure("example.test", ctx=ctx)

    assert result.status is None
    assert result.error_code == code
    assert result.error is not None
    assert len(ctx.errors) == 1
    recorded = ctx.errors[0]
    assert recorded.code == code
    assert recorded.source == "http:example.test"


def test_measure_marks_timeout_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    """超时属于可重试错误，网络类亦然；上报字段必须一致。"""
    monkeypatch.setattr(
        probes_http.httpx,
        "Client",
        lambda **kwargs: _RaisingClient(httpx.ReadTimeout("读超时")),
    )
    ctx = ProbeContext.with_budget(5.0)

    result = probes_http.measure("example.test", ctx=ctx)

    assert result.error_code == ProbeErrorCode.TIMEOUT.value
    assert ctx.errors[0].retryable is True
