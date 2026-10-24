# -*- coding: utf-8 -*-
"""DNS 探测测试 —— 只连本机回环上的假 DNS 服务器，绝不访问外网。

覆盖：UDP 成功、错误事务 ID 不算成功、短报文判解析失败、``TC`` 截断回落 TCP、
IPv6（``::1`` 不可用时跳过）、``benchmark`` 取平均与失败保留原因。
"""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
from collections.abc import Iterator

import pytest

from netopt import probes_dns
from netopt.domain.codes import ProbeErrorCode
from netopt.probes import ProbeContext

_HOST = "example.test"
_VALID_FLAGS = 0x8180  # QR + RD + RA
_TRUNCATED_FLAGS = 0x8200  # QR + TC


def _reply(query: bytes, *, flags: int = _VALID_FLAGS, tid_delta: int = 0) -> bytes:
    """构造最小应答：按需改事务 ID、置 flags，并回显问题段。"""
    (tid,) = struct.unpack(">H", query[:2])
    reply_id = (tid + tid_delta) & 0xFFFF
    return struct.pack(">HHHHHH", reply_id, flags, 1, 0, 0, 0) + query[12:]


def _read_exact(sock: socket.socket, size: int) -> bytes:
    """从 TCP 流读满指定字节数。"""
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("对端提前关闭")
        buf += chunk
    return buf


@contextlib.contextmanager
def _udp_server(
    *,
    family: socket.AddressFamily = socket.AF_INET,
    host: str = "127.0.0.1",
    flags: int = _VALID_FLAGS,
    tid_delta: int = 0,
    raw: bytes | None = None,
) -> Iterator[int]:
    """起一个随机端口的回环 UDP DNS 服务器（线程内应答固定报文）。"""
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((host, 0))
    sock.settimeout(0.2)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def _run() -> None:
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                payload = raw if raw is not None else _reply(data, flags=flags, tid_delta=tid_delta)
                sock.sendto(payload, addr)
            except OSError:
                return

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        sock.close()
        thread.join(timeout=1.0)


def _bind_tcp_udp_pair() -> tuple[socket.socket, socket.socket, int]:
    """申请一对同号的 TCP/UDP 回环端口。

    Windows 的 TCP 与 UDP 端口空间独立，``bind(("127.0.0.1", 0))`` 拿到的
    端口可能刚好被别的 UDP socket 占用；并行跑测试时这种碰撞概率会上升，
    所以失败就换一个端口重试，而不是让整个用例挂掉。
    """
    for _ in range(20):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", 0))
        port = tcp.getsockname()[1]
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp.bind(("127.0.0.1", port))
        except OSError:
            udp.close()
            tcp.close()
            continue
        tcp.listen(1)
        return tcp, udp, port
    raise RuntimeError("连续 20 次都拿不到同号的 TCP/UDP 回环端口")


@contextlib.contextmanager
def _truncating_server() -> Iterator[int]:
    """同一端口上同时起 UDP（回 ``TC``）与 TCP（回完整应答）的 DNS 服务器。"""
    tcp, udp, port = _bind_tcp_udp_pair()
    tcp.settimeout(0.2)
    udp.settimeout(0.2)
    stop = threading.Event()
    udp_ready = threading.Event()
    tcp_ready = threading.Event()

    def _udp_run() -> None:
        udp_ready.set()
        while not stop.is_set():
            try:
                data, addr = udp.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                udp.sendto(_reply(data, flags=_TRUNCATED_FLAGS), addr)
            except OSError:
                return

    def _tcp_run() -> None:
        tcp_ready.set()
        while not stop.is_set():
            try:
                conn, _addr = tcp.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with conn:
                    conn.settimeout(5.0)
                    (length,) = struct.unpack(">H", _read_exact(conn, 2))
                    payload = _reply(_read_exact(conn, length))
                    conn.sendall(struct.pack(">H", len(payload)) + payload)
            except OSError:
                continue

    threads = [
        threading.Thread(target=_udp_run, daemon=True),
        threading.Thread(target=_tcp_run, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        # 等两个线程真正跑起来再发查询，避免高负载下线程尚未调度就超时。
        assert udp_ready.wait(timeout=2.0), "UDP DNS 服务线程未就绪"
        assert tcp_ready.wait(timeout=2.0), "TCP DNS 服务线程未就绪"
        yield port
    finally:
        stop.set()
        udp.close()
        tcp.close()
        for thread in threads:
            thread.join(timeout=2.0)


def _ipv6_loopback_available() -> bool:
    """本机是否能绑定 ``::1``。"""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::1", 0))
    except OSError:
        return False
    return True


# ===========================================================================
# 单次查询
# ===========================================================================
def test_query_udp_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """合法应答：拿到耗时，传输层是 UDP，不产生错误记录。"""
    ctx = ProbeContext.with_budget(5.0)
    with _udp_server() as port:
        monkeypatch.setattr(probes_dns, "_DNS_PORT", port)
        result = probes_dns.query("127.0.0.1", _HOST, timeout=1.0, ctx=ctx)

    assert result.error is None
    assert result.error_code is None
    assert result.transport == "udp"
    assert result.elapsed_ms is not None
    assert result.elapsed_ms >= 0.0
    assert result.server == "127.0.0.1"
    assert result.host == _HOST
    assert ctx.errors == []


def test_query_wrong_transaction_id_is_not_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """事务 ID 不匹配的包不能被当成成功，只能等到超时。"""
    with _udp_server(tid_delta=1) as port:
        monkeypatch.setattr(probes_dns, "_DNS_PORT", port)
        result = probes_dns.query("127.0.0.1", _HOST, timeout=0.3)

    assert result.elapsed_ms is None
    assert result.error_code == ProbeErrorCode.TIMEOUT.value
    assert result.error is not None
    assert result.transport == "udp"


def test_query_short_response_is_parse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """不足 12 字节的应答无法解析，应立刻以 parse 失败而不是当成功。"""
    with _udp_server(raw=b"\x00\x00\x00\x00") as port:
        monkeypatch.setattr(probes_dns, "_DNS_PORT", port)
        result = probes_dns.query("127.0.0.1", _HOST, timeout=1.0)

    assert result.elapsed_ms is None
    assert result.error_code == ProbeErrorCode.PARSE.value
    assert result.error is not None


def test_query_falls_back_to_tcp_on_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    """UDP 应答置 TC 时，必须用 TCP 重取同一报文并标 transport="tcp"。"""
    with _truncating_server() as port:
        monkeypatch.setattr(probes_dns, "_DNS_PORT", port)
        result = probes_dns.query("127.0.0.1", _HOST, timeout=5.0)

    assert result.error is None
    assert result.error_code is None
    assert result.transport == "tcp"
    assert result.elapsed_ms is not None
    assert result.elapsed_ms >= 0.0


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="本机没有可用的 IPv6 环回")
def test_query_uses_af_inet6_for_colon_address(monkeypatch: pytest.MonkeyPatch) -> None:
    """地址含 ``:`` 走 AF_INET6；``::1`` 的查询必须能成功。"""
    with _udp_server(family=socket.AF_INET6, host="::1") as port:
        monkeypatch.setattr(probes_dns, "_DNS_PORT", port)
        result = probes_dns.query("::1", _HOST, timeout=1.0)

    assert result.error is None
    assert result.transport == "udp"
    assert result.elapsed_ms is not None


def test_query_records_timeout_in_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """失败必须写入 ProbeContext，且带来源与可重试标记。"""
    ctx = ProbeContext.with_budget(5.0)
    with _udp_server(tid_delta=1) as port:
        monkeypatch.setattr(probes_dns, "_DNS_PORT", port)
        result = probes_dns.query("127.0.0.1", _HOST, timeout=0.3, ctx=ctx)

    assert result.error_code == ProbeErrorCode.TIMEOUT.value
    assert len(ctx.errors) == 1
    recorded = ctx.errors[0]
    assert recorded.code == ProbeErrorCode.TIMEOUT.value
    assert recorded.source == "dns:127.0.0.1"
    assert recorded.retryable is True


def test_query_rejects_empty_host() -> None:
    """空主机名是调用方错误，直接给出 parse 失败，不发包。"""
    result = probes_dns.query("127.0.0.1", "  ", timeout=0.1)

    assert result.elapsed_ms is None
    assert result.error_code == ProbeErrorCode.PARSE.value


# ===========================================================================
# 批量基准
# ===========================================================================
def test_benchmark_averages_successes_and_keeps_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """成功值取平均；全失败的服务器保留错误，且每个服务器都留在结果里。"""
    server_samples = {"192.0.2.1": [10.0, 20.0, 30.0]}
    calls: list[str] = []

    def _fake_query(
        server: str,
        host: str,
        timeout: float = 3.0,
        *,
        ctx: ProbeContext | None = None,
    ) -> probes_dns.DnsResult:
        calls.append(server)
        samples = server_samples.get(server)
        if samples:
            elapsed = samples.pop(0)
            return probes_dns.DnsResult(
                server=server, host=host, elapsed_ms=elapsed, transport="udp"
            )
        return probes_dns.DnsResult(
            server=server,
            host=host,
            elapsed_ms=None,
            error="DNS 查询超时（udp）",
            error_code=ProbeErrorCode.TIMEOUT.value,
        )

    monkeypatch.setattr(probes_dns, "query", _fake_query)
    results = probes_dns.benchmark(["192.0.2.1", "192.0.2.2"], _HOST, attempts=3)

    assert len(results) == 2
    assert results[0].elapsed_ms == pytest.approx(20.0)
    assert results[0].transport == "udp"
    assert results[0].error is None
    assert results[1].elapsed_ms is None
    assert results[1].error == "DNS 查询超时（udp）"
    assert results[1].error_code == ProbeErrorCode.TIMEOUT.value
    assert calls.count("192.0.2.1") == 3
    assert calls.count("192.0.2.2") == 3


def test_benchmark_averages_only_successful_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """部分尝试失败时，平均值只算成功的样本，不把失败当 0。"""
    outcomes = iter(
        [
            probes_dns.DnsResult(server="192.0.2.1", host=_HOST, elapsed_ms=None, error="超时"),
            probes_dns.DnsResult(server="192.0.2.1", host=_HOST, elapsed_ms=40.0, transport="udp"),
            probes_dns.DnsResult(server="192.0.2.1", host=_HOST, elapsed_ms=None, error="超时"),
        ]
    )

    def _fake_query(
        server: str,
        host: str,
        timeout: float = 3.0,
        *,
        ctx: ProbeContext | None = None,
    ) -> probes_dns.DnsResult:
        return next(outcomes)

    monkeypatch.setattr(probes_dns, "query", _fake_query)
    results = probes_dns.benchmark(["192.0.2.1"], _HOST, attempts=3)

    assert len(results) == 1
    assert results[0].elapsed_ms == pytest.approx(40.0)
    assert results[0].error is None
    assert results[0].transport == "udp"
