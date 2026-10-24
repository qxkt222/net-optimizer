# -*- coding: utf-8 -*-
"""多连接并发测速（v2）—— 下载 / 上传带宽探测。

v1 的测速是单线程、每个源串行读取，千兆线路会被单连接窗口大小严重低估。
这里用 ``connections`` 条线程并发跑，以**聚合字节数 / 墙钟时间**计算吞吐。

失败语义：任何一条连接失败都保留其他连接的结果；全部失败才返回
``mbps=None`` 并带 ``error``。不打印、不读写文件；URL 由调用方给出，
本模块自身不访问任何固定外网地址。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import httpx

_USER_AGENT = "net-optimizer/2.0"
_CHUNK = 64 * 1024


@dataclass(frozen=True)
class SpeedResult:
    """一个测速源的结果。

    ``mbps`` 是聚合吞吐（Mbit/s，十进制）；``bytes`` 是成功传输的字节数；
    ``seconds`` 是墙钟耗时；``error`` 非空表示至少一条连接失败。
    全部连接失败时 ``mbps=None``、``bytes=0``。
    """

    name: str
    mbps: float | None
    bytes: int = 0
    seconds: float = 0.0
    error: str | None = None


class _Tally:
    """线程安全的计数器：累计字节与失败原因。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.bytes = 0
        self.errors: list[str] = []

    def add_bytes(self, nbytes: int) -> None:
        with self._lock:
            self.bytes += nbytes

    def add_error(self, message: str) -> None:
        with self._lock:
            self.errors.append(message)


def _mbps(nbytes: int, seconds: float) -> float | None:
    """聚合吞吐（Mbit/s）；没有成功字节或耗时非法时返回 None。"""
    if nbytes <= 0 or seconds <= 0:
        return None
    return nbytes * 8 / seconds / 1_000_000


def _join(threads: list[threading.Thread], wait: float) -> bool:
    """等待所有线程结束；返回是否全部按时退出。"""
    for thread in threads:
        thread.join(timeout=wait)
    return not any(thread.is_alive() for thread in threads)


def _result(name: str, tally: _Tally, started: float) -> SpeedResult:
    """按聚合字节与墙钟耗时组装结果。"""
    seconds = max(0.0, time.monotonic() - started)
    error = "; ".join(tally.errors) if tally.errors else None
    return SpeedResult(
        name=name,
        mbps=_mbps(tally.bytes, seconds),
        bytes=tally.bytes,
        seconds=seconds,
        error=error,
    )


def _client(timeout: float) -> httpx.Client:
    """创建一个直连客户端：不走系统代理，避免代理把测速结果带偏。"""
    return httpx.Client(timeout=httpx.Timeout(timeout), follow_redirects=True, trust_env=False)


def download(
    name: str,
    url: str,
    *,
    connections: int = 4,
    max_seconds: float = 15.0,
    timeout: float = 10.0,
) -> SpeedResult:
    """用 ``connections`` 条并发连接流式下载，返回聚合吞吐。

    每条连接持续读取到 EOF、达到 ``max_seconds`` 或出错为止；总字节数除以
    墙钟时间得到 ``mbps``。单条连接返回非 200 或抛异常只记 ``error``，
    不影响其他连接。
    """
    if connections < 1:
        return SpeedResult(name=name, mbps=None, error="connections 必须 >= 1")
    if max_seconds <= 0:
        return SpeedResult(name=name, mbps=None, error="max_seconds 必须 > 0")

    tally = _Tally()
    started = time.monotonic()
    deadline = started + max_seconds
    request_timeout = max(0.001, min(timeout, max_seconds))

    def worker() -> None:
        try:
            with (
                _client(request_timeout) as client,
                client.stream("GET", url, headers={"User-Agent": _USER_AGENT}) as response,
            ):
                if response.status_code != 200:
                    tally.add_error(f"HTTP {response.status_code}")
                    return
                for chunk in response.iter_raw(_CHUNK):
                    if time.monotonic() >= deadline:
                        return
                    if chunk:
                        tally.add_bytes(len(chunk))
        except Exception as exc:  # 网络异常种类多，保留原因即可
            tally.add_error(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(connections)]
    for thread in threads:
        thread.start()
    if not _join(threads, max_seconds + request_timeout + 1.0):
        tally.add_error("部分连接未在预算内结束")

    return _result(name, tally, started)


def upload(
    name: str,
    url: str,
    *,
    connections: int = 4,
    payload_bytes: int = 4 * 1024 * 1024,
    max_seconds: float = 15.0,
    timeout: float = 10.0,
) -> SpeedResult:
    """用 ``connections`` 条并发连接 POST 负载，返回聚合吞吐。

    每条连接发送 ``payload_bytes // connections`` 字节（余数不发送，与
    ``payload_bytes`` 的实际语义一致）；只有 2xx 响应才计入成功字节。
    单条失败只记 ``error``，不影响其他连接。
    """
    if connections < 1:
        return SpeedResult(name=name, mbps=None, error="connections 必须 >= 1")
    if max_seconds <= 0:
        return SpeedResult(name=name, mbps=None, error="max_seconds 必须 > 0")

    per_connection = payload_bytes // connections
    if per_connection <= 0:
        return SpeedResult(name=name, mbps=None, error="payload_bytes 小于 connections")

    payload = b"\0" * per_connection
    tally = _Tally()
    started = time.monotonic()
    deadline = started + max_seconds
    request_timeout = max(0.001, min(timeout, max_seconds))
    headers = {"User-Agent": _USER_AGENT, "Content-Type": "application/octet-stream"}

    def worker() -> None:
        if time.monotonic() >= deadline:
            tally.add_error("超出预算")
            return
        try:
            with _client(request_timeout) as client:
                response = client.post(url, content=payload, headers=headers)
                response.read()
                if response.status_code >= 400:
                    tally.add_error(f"HTTP {response.status_code}")
                    return
                tally.add_bytes(per_connection)
        except Exception as exc:  # 网络异常种类多，保留原因即可
            tally.add_error(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(connections)]
    for thread in threads:
        thread.start()
    if not _join(threads, max_seconds + request_timeout + 1.0):
        tally.add_error("部分连接未在预算内结束")

    return _result(name, tally, started)
