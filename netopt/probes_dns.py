# -*- coding: utf-8 -*-
"""DNS 探测（v2）—— IPv4/IPv6 双栈、UDP 截断回落 TCP、错误可解释。

与 v1 :func:`netopt.probes.dns_query` 的区别：

- 服务器地址含 ``:`` 时按 :data:`socket.AF_INET6` 建 socket，IPv6-only 环境
  不再被误判成 DNS 故障；
- UDP 应答 ``TC``（截断）置位时，用同一报文走 TCP 重发（2 字节长度前缀），
  并在 :attr:`DnsResult.transport` 标明实际使用的传输层；
- 失败不再一律返回 ``None``：超时 / 网络 / 解析三类分别落
  :class:`netopt.domain.codes.ProbeErrorCode`，同时写入调用方给的
  :class:`netopt.probes.ProbeContext`。

本模块只做一次查询与批量基准，不打印、不读写文件。
"""

from __future__ import annotations

import random
import socket
import struct
import time
from dataclasses import dataclass

from netopt.domain.codes import ProbeErrorCode
from netopt.probes import ProbeContext

#: DNS 服务端口。测试用 ``monkeypatch`` 把它改成回环服务器的随机端口。
_DNS_PORT = 53

_TYPE_A = 1
_CLASS_IN = 1
_FLAG_QR = 0x8000
_FLAG_TC = 0x0200
_MAX_RESPONSE = 4096
_HEADER = struct.Struct(">HHHHHH")


class _DnsTimeout(Exception):
    """内部信号：在截止时间前没等到合法应答。"""


class _DnsParseError(Exception):
    """内部信号：应答报文长度或字段不合法。"""


@dataclass(frozen=True)
class DnsResult:
    """一次 DNS 查询的结果。

    ``elapsed_ms`` 为 ``None`` 表示失败，此时 ``error`` / ``error_code``
    至少有一个非空；``transport`` 是实际完成查询的传输层（``udp`` / ``tcp``）。
    """

    server: str
    host: str
    elapsed_ms: float | None
    transport: str | None = None
    error: str | None = None
    error_code: str | None = None


def _build_query(tid: int, host: str) -> bytes:
    """自组一条 A 查询报文（RD=1，QDCOUNT=1）；主机名不合法时抛 ``ValueError``。"""
    host = host.strip().rstrip(".")
    if not host:
        raise ValueError("主机名为空")
    labels = host.split(".")
    question = b"".join(_encode_label(label) for label in labels)
    question += b"\x00" + struct.pack(">HH", _TYPE_A, _CLASS_IN)
    return _HEADER.pack(tid, 0x0100, 1, 0, 0, 0) + question


def _encode_label(label: str) -> bytes:
    """把单个 DNS 标签编码为「长度 + IDNA 字节」。"""
    if not label:
        raise ValueError("主机名含空标签")
    raw = label.encode("idna")
    if len(raw) > 63:
        raise ValueError("DNS 标签超过 63 字节")
    return bytes([len(raw)]) + raw


def _classify(data: bytes, tid: int) -> str:
    """判定一条 UDP 报文：``ok`` / ``mismatch``（无关包）/ ``parse``。"""
    if len(data) < 12:
        return "parse"
    reply_id, flags = struct.unpack(">HH", data[:4])
    if reply_id != tid or not flags & _FLAG_QR:
        return "mismatch"
    return "ok"


def _recv_udp(sock: socket.socket, tid: int, deadline: float) -> bytes:
    """在截止时间前收一条合法 UDP 应答；无关包丢弃后继续等。"""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _DnsTimeout
        sock.settimeout(remaining)
        try:
            data, _addr = sock.recvfrom(_MAX_RESPONSE)
        except TimeoutError as exc:
            raise _DnsTimeout from exc
        verdict = _classify(data, tid)
        if verdict == "ok":
            return data
        if verdict == "parse":
            raise _DnsParseError
        # mismatch：端口上可能混入无关 UDP 包，继续等真正的事务 ID


def _recv_exact(sock: socket.socket, size: int, deadline: float) -> bytes:
    """从 TCP 流读满 ``size`` 字节；对端提前关闭按解析失败处理。"""
    chunks: list[bytes] = []
    got = 0
    while got < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _DnsTimeout
        sock.settimeout(remaining)
        chunk = sock.recv(size - got)
        if not chunk:
            raise _DnsParseError
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def _exchange_tcp(
    family: socket.AddressFamily,
    server: str,
    payload: bytes,
    tid: int,
    timeout: float,
) -> bytes:
    """把同一报文走 TCP 重发：2 字节长度前缀 + 报文，校验事务 ID 与 QR 位。"""
    deadline = time.monotonic() + timeout
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, _DNS_PORT))
        sock.sendall(struct.pack(">H", len(payload)) + payload)
        (length,) = struct.unpack(">H", _recv_exact(sock, 2, deadline))
        if length < 12:
            raise _DnsParseError
        data = _recv_exact(sock, length, deadline)
    if _classify(data, tid) != "ok":
        raise _DnsParseError
    return data


def _failure(
    server: str,
    host: str,
    code: ProbeErrorCode,
    message: str,
    *,
    transport: str | None = None,
    ctx: ProbeContext | None = None,
    retryable: bool = False,
) -> DnsResult:
    """构造失败结果，并把错误写进共享上下文（若给了）。"""
    if ctx is not None:
        ctx.record_error(code.value, f"dns:{server}", message, retryable=retryable)
    return DnsResult(
        server=server,
        host=host,
        elapsed_ms=None,
        transport=transport,
        error=message,
        error_code=code.value,
    )


def query(
    server: str,
    host: str,
    timeout: float = 3.0,
    *,
    ctx: ProbeContext | None = None,
) -> DnsResult:
    """向 ``server`` 发一条 A 查询，返回耗时与传输层；失败带可解释错误。

    地址含 ``:`` 视为 IPv6 字面量，否则按 IPv4 处理。UDP 应答 ``TC`` 置位时
    自动用 TCP 重试同一报文，``transport`` 随之变为 ``"tcp"``。
    """
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    try:
        # 仅作 DNS 事务 ID 的随机填充，与安全/密码学无关
        tid = random.randint(0, 0xFFFF)  # nosec B311
        payload = _build_query(tid, host)
    except (UnicodeError, ValueError, struct.error) as exc:
        return _failure(server, host, ProbeErrorCode.PARSE, f"DNS 查询报文构造失败：{exc}", ctx=ctx)

    started = time.perf_counter()
    deadline = time.monotonic() + timeout
    transport = "udp"
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (server, _DNS_PORT))
            data = _recv_udp(sock, tid, deadline)
        flags = struct.unpack(">H", data[2:4])[0]
        if flags & _FLAG_TC:
            transport = "tcp"
            _exchange_tcp(family, server, payload, tid, timeout)
    except _DnsTimeout:
        return _failure(
            server,
            host,
            ProbeErrorCode.TIMEOUT,
            f"DNS 查询超时（{transport}）",
            transport=transport,
            ctx=ctx,
            retryable=True,
        )
    except _DnsParseError:
        return _failure(
            server,
            host,
            ProbeErrorCode.PARSE,
            f"DNS 应答报文无法解析（{transport}）",
            transport=transport,
            ctx=ctx,
        )
    except OSError as exc:
        return _failure(
            server,
            host,
            ProbeErrorCode.NETWORK,
            f"DNS 网络错误（{transport}）：{exc}",
            transport=transport,
            ctx=ctx,
            retryable=True,
        )

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return DnsResult(server=server, host=host, elapsed_ms=elapsed_ms, transport=transport)


def benchmark(
    servers: list[str],
    host: str,
    attempts: int = 3,
    *,
    ctx: ProbeContext | None = None,
) -> list[DnsResult]:
    """对每个服务器查 ``attempts`` 次，成功值取平均，失败保留原因。

    返回列表与 ``servers`` 等长且顺序一致：不筛掉慢的，也不只返回最快的；
    某个服务器全部尝试失败时，其结果的 ``elapsed_ms`` 为 ``None``，
    ``error`` / ``error_code`` 保留最后一次失败的原因。
    """
    attempts = max(1, attempts)
    results: list[DnsResult] = []
    for server in servers:
        samples: list[float] = []
        transport: str | None = None
        last_failure: DnsResult | None = None
        for _ in range(attempts):
            result = query(server, host, ctx=ctx)
            if result.elapsed_ms is None:
                last_failure = result
                continue
            samples.append(result.elapsed_ms)
            if transport is None:
                transport = result.transport

        if samples:
            average = sum(samples) / len(samples)
            results.append(
                DnsResult(server=server, host=host, elapsed_ms=average, transport=transport)
            )
        elif last_failure is not None:
            results.append(last_failure)
        else:  # pragma: no cover - attempts >= 1 时不会走到
            results.append(DnsResult(server=server, host=host, elapsed_ms=None))
    return results


__all__ = ["DnsResult", "benchmark", "query"]
