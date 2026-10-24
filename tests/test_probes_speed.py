# -*- coding: utf-8 -*-
"""probes_speed 测试：多连接并发、聚合吞吐与部分失败。

只连本机 ``127.0.0.1`` 的临时 HTTP 服务，不访问外网。
用 ``connections=2`` 与固定 1MB 响应把测试时长压在一秒量级。
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from netopt.probes_speed import download, upload

_BLOB = b"x" * (1024 * 1024)  # 1MB


class _State:
    """服务端共享计数：上传字节、下载请求数、flaky 请求序号。"""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.uploaded = 0
        self.downloads = 0
        self.download_flaky = 0
        self.upload_flaky = 0


def _make_handler(state: _State) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args) -> None:
            """测试期间不往 stderr 打访问日志。"""

        def _send(self, status: int, body: bytes = b"") -> None:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/download":
                with state.lock:
                    state.downloads += 1
                self._send(200, _BLOB)
                return
            if self.path == "/flaky":
                with state.lock:
                    state.download_flaky += 1
                    first = state.download_flaky == 1
                if first:
                    self._send(500)
                else:
                    self._send(200, _BLOB)
                return
            self._send(500)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            with state.lock:
                state.uploaded += len(body)
            if self.path == "/upload":
                self._send(200)
                return
            if self.path == "/upload-flaky":
                with state.lock:
                    state.upload_flaky += 1
                    first = state.upload_flaky == 1
                self._send(500 if first else 200)
                return
            self._send(500)

    return Handler


@pytest.fixture
def speed_server():
    """在本机随机端口起一个临时 HTTP 服务，测试结束立即关闭。"""
    state = _State()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base, state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_download_aggregates_connections(speed_server) -> None:
    """2 条连接各读完 1MB：聚合字节 = 2MB，吞吐为正。"""
    base, state = speed_server
    result = download("local", f"{base}/download", connections=2, max_seconds=5.0, timeout=2.0)

    assert result.name == "local"
    assert result.bytes == 2 * len(_BLOB)
    assert result.mbps is not None and result.mbps > 0
    assert result.seconds > 0
    assert result.error is None
    assert state.downloads == 2


def test_download_partial_failure_keeps_other_connection(speed_server) -> None:
    """一条连接收到 500：另一条的 1MB 仍然计入，error 保留原因。"""
    base, _state = speed_server
    result = download("flaky", f"{base}/flaky", connections=2, max_seconds=5.0, timeout=2.0)

    assert result.bytes == len(_BLOB)
    assert result.mbps is not None and result.mbps > 0
    assert result.error is not None
    assert "HTTP 500" in result.error


def test_download_all_connections_fail(speed_server) -> None:
    """全部连接失败：mbps=None、bytes=0，错误可解释。"""
    base, _state = speed_server
    result = download("fail", f"{base}/fail", connections=2, max_seconds=5.0, timeout=2.0)

    assert result.bytes == 0
    assert result.mbps is None
    assert result.error is not None
    assert "HTTP 500" in result.error


def test_upload_counts_successful_bytes(speed_server) -> None:
    """每条连接发送 payload_bytes // connections；服务端收到同样字节数。"""
    base, state = speed_server
    payload = 512 * 1024
    result = upload(
        "up", f"{base}/upload", connections=2, payload_bytes=payload, max_seconds=5.0, timeout=2.0
    )

    assert result.bytes == payload
    assert state.uploaded == payload
    assert result.mbps is not None and result.mbps > 0
    assert result.error is None


def test_upload_partial_failure_keeps_other_connection(speed_server) -> None:
    """一条上传收到 500：另一条的成功字节仍计入。"""
    base, _state = speed_server
    payload = 512 * 1024
    result = upload(
        "up-flaky",
        f"{base}/upload-flaky",
        connections=2,
        payload_bytes=payload,
        max_seconds=5.0,
        timeout=2.0,
    )

    assert result.bytes == payload // 2
    assert result.mbps is not None and result.mbps > 0
    assert result.error is not None
    assert "HTTP 500" in result.error


def test_upload_all_connections_fail(speed_server) -> None:
    """全部上传失败：mbps=None、bytes=0。"""
    base, _state = speed_server
    result = upload(
        "up-fail",
        f"{base}/upload-fail",
        connections=2,
        payload_bytes=512 * 1024,
        max_seconds=5.0,
        timeout=2.0,
    )

    assert result.bytes == 0
    assert result.mbps is None
    assert result.error is not None
    assert "HTTP 500" in result.error


def test_speed_probes_do_not_print(speed_server, capsys) -> None:
    """测速层不打印（展示是渲染层的职责），服务端访问日志也被静音。"""
    base, _state = speed_server
    download("quiet", f"{base}/download", connections=2, max_seconds=5.0, timeout=2.0)
    upload(
        "quiet",
        f"{base}/upload",
        connections=2,
        payload_bytes=128 * 1024,
        max_seconds=5.0,
        timeout=2.0,
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_invalid_arguments_return_error_without_network() -> None:
    """连接数 / 预算 / 负载非法时立即返回错误，不做任何请求。"""
    bad_connections = download("x", "http://127.0.0.1:1/never", connections=0)
    bad_upload = upload("x", "http://127.0.0.1:1/never", connections=2, payload_bytes=1)

    assert bad_connections.mbps is None and bad_connections.error
    assert bad_upload.mbps is None and bad_upload.error
