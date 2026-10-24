# -*- coding: utf-8 -*-
"""HTTP 探测（v2）—— 用 httpx trace 把一次请求拆成 connect / TLS / TTFB / total。

httpx 0.28 的 ``response.extensions`` **不含** trace（实测只有
``http_version`` / ``network_stream`` / ``reason_phrase``），trace 必须通过
``request.extensions["trace"]`` 的同步回调收集。httpcore 1.0.9 实际发出的事件名
（已在本机 127.0.0.1 明文 HTTP 上实测确认）为::

    connection.connect_tcp.started / .complete
    connection.start_tls.started / .complete
    http11.send_request_headers.started / .complete
    http11.receive_response_headers.started / .complete

四段口径：

- ``connect_ms``：``connect_tcp`` 的 started → complete；
- ``tls_ms``：``start_tls`` 的 started → complete（明文 HTTP 时为 ``None``）；
- ``ttfb_ms``：``send_request_headers`` 完成 → ``receive_response_headers`` 完成；
- ``total_ms``：本模块用 :func:`time.perf_counter` 包住整次 ``GET``，不靠 trace 推算。

本模块只做一次测量，不打印、不读写文件。
"""

from __future__ import annotations

import ssl
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import httpx

from netopt.domain.codes import ProbeErrorCode
from netopt.probes import ProbeContext

_TCP_STARTED = "connection.connect_tcp.started"
_TCP_COMPLETE = "connection.connect_tcp.complete"
_TLS_STARTED = "connection.start_tls.started"
_TLS_COMPLETE = "connection.start_tls.complete"
_SEND_STARTED = "http11.send_request_headers.started"
_SEND_COMPLETE = "http11.send_request_headers.complete"
_RECV_COMPLETE = "http11.receive_response_headers.complete"

#: trace 事件 = (perf_counter 秒, 事件名)。
TraceEvent = tuple[float, str]


@dataclass(frozen=True)
class HttpTiming:
    """一次 HTTP 测量的四段耗时与状态码。

    任何一段取不到就保持 ``None``，绝不填 0 或编造；失败时 ``status`` 也为
    ``None``，原因放在 ``error`` / ``error_code``。
    """

    host: str
    connect_ms: float | None = None
    tls_ms: float | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None
    status: int | None = None
    error: str | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class _Phases:
    """由 trace 推算出的三段耗时（外加显式传入的 total）。"""

    connect_ms: float | None = None
    tls_ms: float | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None


def _span_ms(at: dict[str, float], started: str, complete: str) -> float | None:
    """取一对事件的毫秒差；任一缺失或时间倒流都返回 ``None``。"""
    begin = at.get(started)
    end = at.get(complete)
    if begin is None or end is None or end < begin:
        return None
    return (end - begin) * 1000.0


def _phases_from_trace(
    events: Sequence[TraceEvent],
    *,
    total_ms: float | None = None,
) -> _Phases:
    """纯函数：把带时间戳的 trace 事件折算成四段耗时。

    同名事件取**首次**出现（连接重试会产生多组）；``ttfb`` 优先用
    ``send_request_headers.complete``，缺失时退回 ``.started``。
    """
    at: dict[str, float] = {}
    for stamp, name in events:
        at.setdefault(name, stamp)

    send_done = at.get(_SEND_COMPLETE, at.get(_SEND_STARTED))
    recv_done = at.get(_RECV_COMPLETE)
    ttfb_ms: float | None = None
    if send_done is not None and recv_done is not None and recv_done >= send_done:
        ttfb_ms = (recv_done - send_done) * 1000.0

    return _Phases(
        connect_ms=_span_ms(at, _TCP_STARTED, _TCP_COMPLETE),
        tls_ms=_span_ms(at, _TLS_STARTED, _TLS_COMPLETE),
        ttfb_ms=ttfb_ms,
        total_ms=total_ms,
    )


def _host_for_url(host: str) -> str:
    """IPv6 字面量放进 URL 时必须加方括号。"""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _make_tracer(events: list[TraceEvent]) -> Callable[[str, dict[str, object]], None]:
    """生成 httpcore trace 回调：只记录事件名与本机时间戳。"""

    def _trace(name: str, _info: dict[str, object]) -> None:
        events.append((time.perf_counter(), name))

    return _trace


def _request(
    host: str,
    port: int,
    timeout: float,
    events: list[TraceEvent],
) -> tuple[int, float]:
    """发一次 ``GET /``，返回 ``(状态码, 总耗时毫秒)``；异常交给调用方分类。

    关闭重定向跟随与系统代理（``trust_env=False``）：测的是到目标站点的
    真实链路，代理环境变量既会污染数字，也可能像本机 ``NO_PROXY`` 含
    ``[::1]`` 那样直接把 httpx 的 URL 解析弄崩。
    """
    url = f"https://{_host_for_url(host)}:{port}/"
    with httpx.Client(
        follow_redirects=False,
        timeout=timeout,
        verify=True,
        trust_env=False,
    ) as client:
        started = time.perf_counter()
        response = client.get(
            url,
            headers={"Connection": "close"},
            extensions={"trace": _make_tracer(events)},
        )
        total_ms = (time.perf_counter() - started) * 1000.0
    return response.status_code, total_ms


def _failure(
    host: str,
    code: ProbeErrorCode,
    message: str,
    *,
    ctx: ProbeContext | None,
    retryable: bool = False,
) -> HttpTiming:
    """构造失败结果，并把错误写进共享上下文（若给了）。"""
    if ctx is not None:
        ctx.record_error(code.value, f"http:{host}", message, retryable=retryable)
    return HttpTiming(host=host, error=message, error_code=code.value)


def measure(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    *,
    ctx: ProbeContext | None = None,
) -> HttpTiming:
    """测一次 ``https://host:port/``，返回四段耗时与状态码。

    失败不抛异常：超时 / 连接失败 / 协议错误 / 其他异常分别映射到
    :class:`ProbeErrorCode`，并记录到 ``ctx``。
    """
    events: list[TraceEvent] = []
    try:
        status, total_ms = _request(host, port, timeout, events)
    except httpx.TimeoutException as exc:
        return _failure(
            host,
            ProbeErrorCode.TIMEOUT,
            f"HTTP 探测超时：{exc}",
            ctx=ctx,
            retryable=True,
        )
    except httpx.ConnectError as exc:
        return _failure(
            host,
            ProbeErrorCode.NETWORK,
            f"HTTP 连接失败：{exc}",
            ctx=ctx,
            retryable=True,
        )
    except httpx.HTTPError as exc:
        return _failure(host, ProbeErrorCode.NETWORK, f"HTTP 协议错误：{exc}", ctx=ctx)
    except ssl.SSLError as exc:
        return _failure(
            host,
            ProbeErrorCode.NETWORK,
            f"TLS 握手失败：{exc}",
            ctx=ctx,
            retryable=True,
        )
    except OSError as exc:
        return _failure(
            host,
            ProbeErrorCode.NETWORK,
            f"HTTP 网络错误：{exc}",
            ctx=ctx,
            retryable=True,
        )
    except Exception as exc:  # 探测层不允许异常穿透，统一降级为不可用
        return _failure(host, ProbeErrorCode.UNAVAILABLE, f"HTTP 探测失败：{exc}", ctx=ctx)

    phases = _phases_from_trace(events, total_ms=total_ms)
    return HttpTiming(
        host=host,
        connect_ms=phases.connect_ms,
        tls_ms=phases.tls_ms,
        ttfb_ms=phases.ttfb_ms,
        total_ms=phases.total_ms,
        status=status,
    )


__all__ = ["HttpTiming", "measure"]
