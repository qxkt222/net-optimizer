# -*- coding: utf-8 -*-
"""``netopt.config`` 的测试：默认值、文件读写、环境变量覆盖、原子写入。

所有用例都只用 ``tmp_path``，绝不读写真实的 ``%LOCALAPPDATA%``。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from netopt import config, paths
from netopt.config import Settings, load, save
from netopt.domain import Band, LossPolicy, MtuPolicy, Policy


@pytest.fixture(autouse=True)
def _clean_netopt_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """清掉外部 ``NETOPT_*`` 变量（含 ``NETOPT_HOME``），让断言不受机器环境影响。"""
    for key in list(os.environ):
        if key.startswith("NETOPT_"):
            monkeypatch.delenv(key, raising=False)


def _write(target: Path, text: str) -> Path:
    target.write_text(text, encoding="utf-8")
    return target


def test_load_missing_file_returns_defaults(tmp_path: Path) -> None:
    """文件不存在 → 默认 Settings，且不会顺手创建文件。"""
    target = tmp_path / "config.toml"

    settings = load(target)

    assert settings == Settings()
    assert settings.policy == Policy.default()
    assert settings.ping_targets == ["www.baidu.com"]
    assert settings.dns_servers == ["223.5.5.5", "119.29.29.29"]
    assert settings.http_hosts == ["www.baidu.com"]
    assert settings.language == "zh-CN"
    assert settings.portable is False
    assert not target.exists()


def test_load_without_path_uses_paths_config_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``path=None`` 必须落到 ``paths.config_path()``。"""
    target = _write(tmp_path / "config.toml", 'language = "ja"\n')
    calls: list[Path] = []

    def _fake_config_path() -> Path:
        calls.append(target)
        return target

    monkeypatch.setattr(paths, "config_path", _fake_config_path)

    assert load().language == "ja"
    assert calls == [target]


def test_load_reads_file_and_policy_overrides(tmp_path: Path) -> None:
    """文件里的普通字段与嵌套 policy 都要生效，未覆盖的字段保持默认。"""
    target = _write(
        tmp_path / "config.toml",
        'ping_targets = ["one.example", "two.example"]\n'
        'dns_servers = ["9.9.9.9"]\n'
        'http_hosts = ["host.example"]\n'
        'language = "en-US"\n'
        "portable = true\n"
        "\n"
        "[policy.gateway]\n"
        "good = 3\n"
        "warn = 20\n"
        "poor = 40\n"
        "\n"
        "[policy.loss]\n"
        "tolerate = 1\n"
        "unusable = 30\n"
        "\n"
        "[policy.weights]\n"
        "gateway = 20\n",
    )

    settings = load(target)

    assert settings.ping_targets == ["one.example", "two.example"]
    assert settings.dns_servers == ["9.9.9.9"]
    assert settings.http_hosts == ["host.example"]
    assert settings.language == "en-US"
    assert settings.portable is True
    assert settings.policy.gateway == Band(good=3, warn=20, poor=40)
    assert settings.policy.loss == LossPolicy(tolerate=1, unusable=30)
    assert settings.policy.weights["gateway"] == 20
    # 只写了一部分的嵌套表，其余字段仍取默认值。
    assert settings.policy.wan == Policy.default().wan
    assert settings.policy.weights["wan"] == Policy.default().weights["wan"]


def test_save_load_roundtrip_with_chinese_and_policy(tmp_path: Path) -> None:
    """save → load 往返一致；中文、列表、嵌套 policy 都不走样。"""
    target = tmp_path / "nested" / "config.toml"
    policy = Policy(
        gateway=Band(good=2, warn=10, poor=20),
        wan=Band(good=40, warn=120, poor=180),
        dns=Band(good=25, warn=90, poor=190),
        http_ttfb=Band(good=100, warn=400, poor=900),
        loss=LossPolicy(tolerate=1, unusable=40),
        mtu=MtuPolicy(standard=1500, pppoe=1492, low=1380),
        weights={"gateway": 20, "wan": 20, "dns": 20, "http": 20, "mtu": 20},
    )
    original = Settings(
        policy=policy,
        ping_targets=["百度.cn", "测试.example"],
        dns_servers=["223.5.5.5"],
        http_hosts=["例子.example"],
        language="zh-CN",
        portable=True,
    )

    save(original, target)

    assert target.exists()
    text = target.read_text(encoding="utf-8")
    assert "百度.cn" in text  # 中文按 UTF-8 原样写入，不是 \u 转义
    assert "\\u767e" not in text
    assert load(target) == original


def test_save_default_roundtrip(tmp_path: Path) -> None:
    """默认配置也能无损往返（浮点阈值写成 5.0 之类，读回仍是同一模型）。"""
    target = tmp_path / "config.toml"

    save(Settings(), target)

    assert load(target) == Settings()
    assert Policy.default() == load(target).policy


def test_env_overrides_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``NETOPT_*`` 环境变量优先于文件；嵌套用 ``__`` 精准覆盖。"""
    target = _write(
        tmp_path / "config.toml",
        'language = "en-US"\n\n[policy.wan]\ngood = 30\nwarn = 100\npoor = 150\n',
    )
    monkeypatch.setenv("NETOPT_LANGUAGE", "en")
    monkeypatch.setenv("NETOPT_POLICY__WAN__WARN", "120")

    settings = load(target)

    assert settings.language == "en"
    assert settings.policy.wan.warn == 120
    assert settings.policy.wan.good == 30
    assert settings.policy.wan.poor == 150


def test_env_nested_override_without_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """没有配置文件时，嵌套环境变量也要能只改一个字段（其余取默认）。"""
    monkeypatch.setenv("NETOPT_POLICY__WAN__WARN", "120")

    settings = load(tmp_path / "missing.toml")

    assert settings.policy.wan == Band(good=30, warn=120, poor=150)


def test_env_overrides_list_and_bool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """列表按 JSON 解析、布尔按 pydantic 规则解析。"""
    monkeypatch.setenv("NETOPT_PING_TARGETS", '["a.example", "b.example"]')
    monkeypatch.setenv("NETOPT_PORTABLE", "true")

    settings = load(tmp_path / "missing.toml")

    assert settings.ping_targets == ["a.example", "b.example"]
    assert settings.portable is True


def test_invalid_toml_raises_value_error(tmp_path: Path) -> None:
    """语法错误的 TOML 必须抛 ValueError（TOMLDecodeError 是其子类）。"""
    target = _write(tmp_path / "config.toml", "language = [unterminated\n")

    with pytest.raises(ValueError):
        load(target)


@pytest.mark.parametrize(
    "payload",
    [
        "bogus = 1\n",
        "[policy.bogus]\nx = 1\n",
        "[policy.wan]\nbogus = 1\n",
    ],
)
def test_unknown_key_raises_value_error(tmp_path: Path, payload: str) -> None:
    """拼错的配置键（含嵌套）必须明确报错，不能静默忽略。"""
    target = _write(tmp_path / "config.toml", payload)

    with pytest.raises(ValueError, match="未知配置项"):
        load(target)


@pytest.mark.parametrize(
    "payload",
    [
        "language = 123\n",
        'portable = "maybe"\n',
        "[policy.wan]\ngood = 100\nwarn = 50\npoor = 10\n",
    ],
)
def test_invalid_field_value_raises_validation_error(tmp_path: Path, payload: str) -> None:
    """字段值非法（类型错、阈值顺序错）必须抛 ValidationError。"""
    target = _write(tmp_path / "config.toml", payload)

    with pytest.raises(ValidationError):
        load(target)


def test_save_creates_parent_directories(tmp_path: Path) -> None:
    """父目录不存在时自动创建，而不是抛 FileNotFoundError。"""
    target = tmp_path / "deep" / "nested" / "config.toml"

    save(Settings(language="en"), target)

    assert load(target).language == "en"


def test_save_failure_keeps_original_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """原子写失败时原文件保持原样，且不遗留临时文件。"""
    # conftest 会在 tmp_path 下建 state/，这里用子目录隔离，只观察配置目录。
    base = tmp_path / "config-dir"
    base.mkdir()
    target = _write(base / "config.toml", 'language = "old"\n')

    def _boom(src: str, dst: str) -> None:
        raise OSError("模拟替换失败")

    monkeypatch.setattr(config.os, "replace", _boom)

    with pytest.raises(OSError, match="模拟替换失败"):
        save(Settings(language="new"), target)

    assert target.read_text(encoding="utf-8") == 'language = "old"\n'
    assert [path.name for path in base.iterdir()] == ["config.toml"]


def test_save_leaves_no_temp_files(tmp_path: Path) -> None:
    """成功保存后目录里只应有目标文件本身。"""
    base = tmp_path / "config-dir"
    target = base / "config.toml"

    save(Settings(language="en"), target)

    assert [path.name for path in base.iterdir()] == ["config.toml"]
