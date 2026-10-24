# -*- coding: utf-8 -*-
"""更新检查测试 —— 全部使用假客户端，绝不访问外网。

覆盖：正常新版本 / 同版本 / 旧版本、预发布排序、``v`` 前缀、404、超时、
非法 JSON、坏响应体，以及默认客户端的 ``trust_env=False`` 构造参数。
"""

from __future__ import annotations

from typing import Any, ClassVar

import httpx
import pytest

import netopt
from netopt import update

_URL = update._LATEST_RELEASE_URL
_RELEASE_URL = "https://github.com/qxkt222/net-optimizer/releases/tag/v2.1.0"


def _response(
    payload: Any = None,
    *,
    status_code: int = 200,
    content: bytes | None = None,
) -> httpx.Response:
    """构造一个不经过网络的真实 ``httpx.Response``。"""
    request = httpx.Request("GET", _URL)
    if content is not None:
        return httpx.Response(status_code, content=content, request=request)
    return httpx.Response(status_code, json=payload, request=request)


def _release(tag: str, url: str = _RELEASE_URL) -> httpx.Response:
    """GitHub Releases API 的成功响应（只保留本模块用到的字段）。"""
    return _response({"tag_name": tag, "html_url": url})


class _FakeClient:
    """记录请求 URL，返回预设响应或抛出预设异常。"""

    def __init__(
        self,
        response: httpx.Response | None = None,
        exc: BaseException | None = None,
    ) -> None:
        self._response = response
        self._exc = exc
        self.urls: list[str] = []

    def get(self, url: str) -> httpx.Response:
        self.urls.append(url)
        if self._exc is not None:
            raise self._exc
        assert self._response is not None
        return self._response


# ===========================================================================
# 成功路径：是否有新版本
# ===========================================================================
def test_check_reports_newer_release() -> None:
    """v2.1.0 相对 2.0.0 应标记为可更新，并原样带出发布页地址。"""
    client = _FakeClient(_release("v2.1.0"))

    info = update.check("2.0.0", client=client)

    assert info == update.UpdateInfo(
        current="2.0.0",
        latest="2.1.0",
        url=_RELEASE_URL,
        available=True,
        error=None,
    )
    assert client.urls == [_URL]


def test_check_same_version_is_not_available() -> None:
    """同版本不算更新。"""
    info = update.check("2.1.0", client=_FakeClient(_release("v2.1.0")))

    assert info.available is False
    assert info.latest == "2.1.0"
    assert info.error is None


def test_check_older_release_is_not_available() -> None:
    """远端比本机还旧时不能提示更新。"""
    info = update.check("2.2.0", client=_FakeClient(_release("v2.1.0")))

    assert info.available is False
    assert info.error is None


def test_check_defaults_to_package_version() -> None:
    """``current`` 缺省取 ``netopt.__version__``。"""
    info = update.check(client=_FakeClient(_release("v999.0.0")))

    assert info.current == netopt.__version__
    assert info.available is True


def test_check_tolerates_missing_html_url() -> None:
    """缺少 html_url 时仍能判断版本，只是没有可展示的链接。"""
    info = update.check("2.0.0", client=_FakeClient(_response({"tag_name": "v2.1.0"})))

    assert info.available is True
    assert info.url is None
    assert info.error is None


# ===========================================================================
# 版本比较：形式与预发布
# ===========================================================================
@pytest.mark.parametrize(
    ("current", "tag", "available"),
    [
        ("v2.0.0", "v2.1.0", True),
        ("2.0.0", "V2.1.0", True),
        ("1.2", "1.2.0", False),
        ("1.2.0", "1.3", True),
        ("2.0.0", "2.0.0.0", False),
        ("2.0.0.dev0", "2.0.0", True),
        ("2.0.0.dev0", "2.0.0.dev1", True),
        ("2.0.0.dev1", "2.0.0.dev0", False),
        ("2.0.0.dev1", "2.0.0.dev1", False),
        ("2.0.0", "2.0.0.dev1", False),
        ("2.0.0rc1", "2.0.0", True),
        ("2.0.0a1", "2.0.0b1", True),
        ("2.0.0", "2.0.1.dev0", True),
    ],
)
def test_version_ordering(current: str, tag: str, available: bool) -> None:
    """带 ``v`` 前缀、缺省段、预发布都按预期排序。"""
    info = update.check(current, client=_FakeClient(_release(tag)))

    assert info.available is available
    assert info.error is None


# ===========================================================================
# 客户端构造：默认客户端必须关闭系统代理
# ===========================================================================
class _RecordingClient:
    """记录 ``httpx.Client`` 的构造参数，并按上下文管理器协议工作。"""

    captured: ClassVar[dict[str, Any]] = {}
    response: ClassVar[httpx.Response | None] = None
    urls: ClassVar[list[str]] = []

    def __init__(self, **kwargs: Any) -> None:
        type(self).captured = kwargs
        type(self).urls = []

    def __enter__(self) -> _RecordingClient:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, url: str) -> httpx.Response:
        type(self).urls.append(url)
        assert type(self).response is not None
        return type(self).response


def test_default_client_disables_environment_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """默认客户端必须以 ``trust_env=False`` 构造，并按入参传递超时。"""
    _RecordingClient.response = _release("v2.1.0")
    monkeypatch.setattr(update.httpx, "Client", _RecordingClient)

    info = update.check("2.0.0", timeout=2.5)

    assert info.error is None
    assert _RecordingClient.captured["trust_env"] is False
    assert _RecordingClient.captured["timeout"] == 2.5
    assert _RecordingClient.urls == [_URL]


def test_injected_client_skips_default_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    """注入 client 时不应再构造默认客户端（测试永远不联网）。"""

    def _boom(**kwargs: Any) -> Any:
        raise AssertionError("注入 client 时不应构造 httpx.Client")

    monkeypatch.setattr(update.httpx, "Client", _boom)

    info = update.check("1.0.0", client=_FakeClient(_release("v2.0.0")))

    assert info.error is None
    assert info.available is True


def test_client_construction_failure_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """客户端本身构造失败时也不抛异常。"""

    def _boom(**kwargs: Any) -> Any:
        raise RuntimeError("无法创建客户端")

    monkeypatch.setattr(update.httpx, "Client", _boom)

    info = update.check("2.0.0")

    assert info.available is False
    assert info.latest is None
    assert info.error is not None


# ===========================================================================
# 失败路径：都返回 error，绝不抛异常
# ===========================================================================
def test_check_404_returns_error_without_raising() -> None:
    """HTTP 404（仓库没有正式发布）折算成错误结果。"""
    client = _FakeClient(_response({"message": "Not Found"}, status_code=404))

    info = update.check("2.0.0", client=client)

    assert info.available is False
    assert info.latest is None
    assert info.url is None
    assert info.error is not None
    assert "404" in info.error


def test_check_client_raised_status_error_returns_error() -> None:
    """客户端直接从 ``get`` 抛 HTTPStatusError 时同样不穿透。"""
    response = _response({"message": "Not Found"}, status_code=404)
    error = httpx.HTTPStatusError("Not Found", request=response.request, response=response)

    info = update.check("2.0.0", client=_FakeClient(exc=error))

    assert info.available is False
    assert info.error is not None
    assert "404" in info.error


def test_check_timeout_returns_error_without_raising() -> None:
    """超时折算成错误结果。"""
    info = update.check("2.0.0", client=_FakeClient(exc=httpx.ReadTimeout("读超时")))

    assert info.available is False
    assert info.latest is None
    assert info.error is not None
    assert "超时" in info.error


def test_check_invalid_json_returns_error_without_raising() -> None:
    """响应不是 JSON 时折算成错误结果。"""
    client = _FakeClient(_response(content=b"<html>not json</html>"))

    info = update.check("2.0.0", client=client)

    assert info.available is False
    assert info.latest is None
    assert info.error is not None


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"html_url": _RELEASE_URL},
        {"tag_name": ""},
        {"tag_name": "nightly"},
    ],
)
def test_check_bad_payload_returns_error(payload: Any) -> None:
    """JSON 结构不对或版本号无法解析时折算成错误结果。"""
    info = update.check("2.0.0", client=_FakeClient(_response(payload)))

    assert info.available is False
    assert info.latest is None
    assert info.url is None
    assert info.error is not None
