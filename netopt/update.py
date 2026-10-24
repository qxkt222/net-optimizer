# -*- coding: utf-8 -*-
"""更新检查（v2）—— 查询 GitHub Releases，只提示是否有新版本。

设计约束（见 ``docs/SPEC.md`` §14）：本模块只做一次只读 HTTP 查询，
**不打印、不写文件、不下载、不安装**。任何网络或响应解析失败都折叠成
:class:`UpdateInfo` 的 ``error`` 字段，绝不向上抛异常，调用方可以放心地
把它放在启动路径上。

版本比较使用本模块自带的轻量解析器（不引入 ``packaging``）：

- 支持 ``1.2.3`` / ``v1.2.3`` / ``2.0.0.dev0`` 等形式；
- 缺省段按 0 补齐（``1.2`` 与 ``1.2.0`` 相等）；
- 预发布（``dev`` / ``a`` / ``b`` / ``rc``）低于同号正式版，
  ``dev`` 之间再按序号比较（``dev0`` < ``dev1``）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import httpx

import netopt

#: GitHub「最新正式发布」接口；预发布不会出现在这里。
_LATEST_RELEASE_URL = "https://api.github.com/repos/qxkt222/net-optimizer/releases/latest"

#: 版本号 = 可选 ``v`` 前缀 + 数字段 + 可选预发布阶段。
_VERSION_RE = re.compile(
    r"^v?(?P<release>\d+(?:\.\d+)*)(?:[._-]?(?P<stage>dev|alpha|beta|rc|a|b)(?P<number>\d*))?$",
    re.IGNORECASE,
)

#: 阶段排序：dev < a/alpha < b/beta < rc < 正式版。
_STAGE_RANK = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "rc": 3, "": 4}


@dataclass(frozen=True)
class UpdateInfo:
    """一次更新检查的结果。

    ``error`` 非空时其余版本字段保持保守：``latest`` / ``url`` 为 ``None``、
    ``available`` 为 ``False``，调用方无需区分“没有新版本”和“检查失败”以外
    的中间状态。
    """

    current: str
    latest: str | None
    url: str | None
    available: bool
    error: str | None = None


@dataclass(frozen=True)
class _ParsedVersion:
    """版本号的可比较形式：数字段 + 阶段序号 + 阶段内序号。"""

    release: tuple[int, ...]
    stage: int
    number: int


def _parse_version(text: str) -> _ParsedVersion | None:
    """解析版本字符串；无法识别时返回 ``None``（不猜、不抛）。"""
    match = _VERSION_RE.match(text.strip())
    if match is None:
        return None
    release = tuple(int(part) for part in match.group("release").split("."))
    stage = (match.group("stage") or "").lower()
    number = int(match.group("number") or "0")
    return _ParsedVersion(release=release, stage=_STAGE_RANK[stage], number=number)


def _is_newer(latest: _ParsedVersion, current: _ParsedVersion) -> bool:
    """``latest`` 是否严格新于 ``current``；缺省数字段按 0 补齐。"""
    width = max(len(latest.release), len(current.release))
    left = latest.release + (0,) * (width - len(latest.release))
    right = current.release + (0,) * (width - len(current.release))
    return (left, latest.stage, latest.number) > (right, current.stage, current.number)


def _failure(current: str, message: str) -> UpdateInfo:
    """构造失败结果：不保留可能误导的半成品数据。"""
    return UpdateInfo(current=current, latest=None, url=None, available=False, error=message)


def _evaluate(client: Any, current: str) -> UpdateInfo:
    """用给定客户端取一次最新发布并折算成 :class:`UpdateInfo`。

    ``client`` 只要求实现 ``get(url) -> response``，response 需要
    ``raise_for_status()`` / ``json()``（与 ``httpx.Client`` 一致）。
    """
    try:
        response = client.get(_LATEST_RELEASE_URL)
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException as exc:
        return _failure(current, f"检查更新超时：{exc}")
    except httpx.HTTPStatusError as exc:
        return _failure(current, f"检查更新失败：HTTP {exc.response.status_code}")
    except httpx.HTTPError as exc:
        return _failure(current, f"检查更新网络错误：{exc}")
    except ValueError as exc:  # response.json() 对非法 JSON 抛 JSONDecodeError
        return _failure(current, f"检查更新响应不是合法 JSON：{exc}")
    except Exception as exc:  # 边界层：任何实现异常都降级为“检查失败”
        return _failure(current, f"检查更新失败：{exc}")

    if not isinstance(payload, dict):
        return _failure(current, "检查更新响应格式无效：期望 JSON 对象")
    tag = payload.get("tag_name")
    if not isinstance(tag, str) or not tag.strip():
        return _failure(current, "检查更新响应缺少 tag_name")

    # GitHub 的 tag 习惯带 ``v`` 前缀，报告里统一用不带前缀的版本号。
    latest = tag.strip()
    if latest[:1] in ("v", "V"):
        latest = latest[1:]

    html_url = payload.get("html_url")
    url = html_url if isinstance(html_url, str) and html_url else None

    parsed_latest = _parse_version(latest)
    parsed_current = _parse_version(current)
    if parsed_latest is None:
        return _failure(current, f"无法解析最新版本号：{tag!r}")
    if parsed_current is None:
        return _failure(current, f"无法解析当前版本号：{current!r}")

    return UpdateInfo(
        current=current,
        latest=latest,
        url=url,
        available=_is_newer(parsed_latest, parsed_current),
    )


def check(
    current: str | None = None,
    *,
    timeout: float = 5.0,
    client: Any | None = None,
) -> UpdateInfo:
    """查询 GitHub Releases，判断是否有比 ``current`` 更新的版本。

    ``current`` 缺省取 :data:`netopt.__version__`。``client`` 供测试注入：
    传入时由调用方负责关闭；未传入时按
    ``httpx.Client(trust_env=False, timeout=timeout)`` 新建并关闭，
    关闭 ``trust_env`` 是为了不让系统代理环境变量影响检查结果。
    """
    current_version = netopt.__version__ if current is None else current
    if client is not None:
        return _evaluate(client, current_version)
    try:
        with httpx.Client(trust_env=False, timeout=timeout) as http_client:
            return _evaluate(http_client, current_version)
    except Exception as exc:  # 连客户端都建不起来时同样降级为“检查失败”
        return _failure(current_version, f"检查更新失败：{exc}")


__all__ = ["UpdateInfo", "check"]
