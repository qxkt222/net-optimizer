# -*- coding: utf-8 -*-
"""v2 配置层 —— ``config.toml`` 的读取、环境变量覆盖与原子保存。

配置文件默认位于 :func:`netopt.paths.config_path`
（``%LOCALAPPDATA%\\net-optimizer\\config.toml``，可用 ``NETOPT_HOME`` 重定向）。
取值优先级从低到高：

1. 字段默认值（见 :class:`Settings` 与 :class:`~netopt.domain.policy.Policy`）；
2. ``config.toml``；
3. 环境变量：前缀 ``NETOPT_``，嵌套用 ``__`` 分隔，例如
   ``NETOPT_LANGUAGE=en``、``NETOPT_POLICY__WAN__WARN=120``。

``config.toml`` 是用户手写的文档，出现未知键会直接抛 :class:`ValueError`
（拼错必须响亮）；环境变量是进程环境，其中的 ``NETOPT_HOME`` 等非配置项
会被忽略 —— 两者语义不同，不做同样的处理。

本轮只提供 :func:`load` / :func:`save`，CLI 接线留给后续任务。
"""

from __future__ import annotations

import contextlib
import math
import os
import re
import tempfile
import tomllib
from collections.abc import Mapping
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    InitSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from netopt import paths
from netopt.domain import Policy

__all__ = ["Settings", "load", "save"]

#: 仅含 ASCII 字母、数字、下划线、连字符的键/表名可以不加引号。
_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")

#: TOML 基本字符串里需要转义的字符（控制字符另行按 ``\uXXXX`` 处理）。
_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}

#: ``load`` 解析出的文件数据（已并入默认值）；由 ``settings_customise_sources``
#: 在构造 :class:`Settings` 时取出。用 ContextVar 而不是类属性，是为了让并发
#: 调用 ``load`` 时互不影响。
_file_values: ContextVar[dict[str, Any] | None] = ContextVar(
    "netopt_config_file_values", default=None
)


class Settings(BaseSettings):
    """运行期配置。

    字段默认值就是开箱即用的行为；``policy`` 承载全部阈值与权重，见
    :class:`~netopt.domain.policy.Policy`。

    ``extra="ignore"`` 是必须的：``NETOPT_HOME`` 等环境变量同样带 ``NETOPT_``
    前缀，但它们不是配置字段，不能因为多看一眼就报错。文件里的未知键由
    :func:`_reject_unknown_keys` 单独拦截。
    """

    model_config = SettingsConfigDict(
        env_prefix="NETOPT_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    policy: Policy = Field(default_factory=Policy.default)
    ping_targets: list[str] = ["www.baidu.com"]
    dns_servers: list[str] = ["223.5.5.5", "119.29.29.29"]
    http_hosts: list[str] = ["www.baidu.com"]
    language: str = "zh-CN"
    portable: bool = False

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """把配置文件插在环境变量之后：环境变量覆盖文件。"""
        file_settings = InitSettingsSource(settings_cls, dict(_file_values.get() or {}))
        return (
            init_settings,
            env_settings,
            file_settings,
            dotenv_settings,
            file_secret_settings,
        )


def load(path: Path | None = None) -> Settings:
    """读取配置并应用环境变量覆盖；``path=None`` 时用默认路径。

    文件不存在返回默认配置。非法 TOML 抛 :class:`tomllib.TOMLDecodeError`
    （:class:`ValueError` 的子类），未知键抛 :class:`ValueError`，字段值非法
    抛 pydantic 的 ``ValidationError`` —— 一律显式失败，不静默回退。
    """
    target = Path(path) if path is not None else paths.config_path()
    data = _read_toml(target)
    _reject_unknown_keys(data, Settings)
    token = _file_values.set(_deep_merge(_default_values(), data))
    try:
        return Settings()
    finally:
        _file_values.reset(token)


def save(settings: Settings, path: Path | None = None) -> None:
    """把配置写成 TOML；``path=None`` 时用默认路径。

    只写传入的对象，不读取环境变量；父目录不存在会自动创建。先写同目录下的
    临时文件，内容落盘后再 ``os.replace`` 原子替换，避免中途失败留下半截配置
    或弄丢原文件。
    """
    target = Path(path) if path is not None else paths.config_path()
    text = _dumps(settings.model_dump())
    target.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def _read_toml(path: Path) -> dict[str, Any]:
    """读取并解析 TOML；文件不存在返回空表（即全部走默认值）。"""
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _default_values() -> dict[str, Any]:
    """取字段默认值（不触发环境变量读取），作为文件数据的兜底。

    ``model_construct()`` 绕过 ``BaseSettings`` 的来源装配，因此这里拿到的
    是纯粹的字段默认值；先并入默认值再交给配置来源，嵌套表只写一部分
    （如只写 ``[policy.wan] warn = 120``）时其余字段才不会丢失。
    """
    return Settings.model_construct().model_dump()


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    """递归合并两个表：``override`` 优先，字典逐层合并而不是整体替换。"""
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _reject_unknown_keys(
    table: Mapping[str, Any], model: type[BaseModel], prefix: str = ""
) -> None:
    """拒绝配置文件里的未知键（含嵌套模型），拼错必须报错。"""
    for key, value in table.items():
        field = model.model_fields.get(key)
        if field is None:
            raise ValueError(f"未知配置项: {prefix}{key}")
        annotation = field.annotation
        if (
            isinstance(value, Mapping)
            and isinstance(annotation, type)
            and issubclass(annotation, BaseModel)
        ):
            _reject_unknown_keys(value, annotation, f"{prefix}{key}.")


def _dumps(data: Mapping[str, Any]) -> str:
    """受限的 TOML 序列化：str / int / float / bool / list / 嵌套表。

    ``save`` 只面对 :attr:`Settings` 的字段类型，不值得引入写侧依赖；
    遇到范围外的类型直接抛 :class:`TypeError`。
    """
    lines: list[str] = []
    _emit_table(data, (), lines)
    return "\n".join(lines) + "\n"


def _emit_table(table: Mapping[str, Any], prefix: tuple[str, ...], lines: list[str]) -> None:
    """先写标量键，再按 ``[a.b]`` 表头递归写子表 —— TOML 要求标量在前。"""
    scalars = [(key, value) for key, value in table.items() if not isinstance(value, Mapping)]
    subtables = [(key, value) for key, value in table.items() if isinstance(value, Mapping)]
    for key, value in scalars:
        lines.append(f"{_format_key(key)} = {_format_value(value)}")
    for key, value in subtables:
        path = (*prefix, key)
        # 只有「自己带标量键」或「空表」才需要表头；纯中转表可以省略，
        # 子表用全路径写出来即可（TOML 会隐式创建父表）。
        if not value or any(not isinstance(item, Mapping) for item in value.values()):
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("[" + ".".join(_format_key(part) for part in path) + "]")
        _emit_table(value, path, lines)


def _format_key(key: str) -> str:
    """裸键原样输出，含特殊字符时用带引号的键。"""
    return key if _BARE_KEY.fullmatch(key) else _quote(key)


def _format_value(value: object) -> str:
    """把 Python 标量/列表渲染成 TOML 值。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"TOML 无法表示非有限浮点数: {value!r}")
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_format_value(item) for item in value) + "]"
    raise TypeError(f"save() 不支持的类型: {type(value).__name__}（值: {value!r}）")


def _quote(text: str) -> str:
    """渲染 TOML 基本字符串：中文原样保留，只转义必须转义的字符。"""
    chunks = ['"']
    for char in text:
        escaped = _ESCAPES.get(char)
        if escaped is not None:
            chunks.append(escaped)
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            chunks.append(f"\\u{ord(char):04x}")
        else:
            chunks.append(char)
    chunks.append('"')
    return "".join(chunks)
