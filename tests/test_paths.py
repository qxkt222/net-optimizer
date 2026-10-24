# -*- coding: utf-8 -*-
"""运行期目录解析测试 —— 不触碰真实用户目录，全部用 monkeypatch + tmp_path。"""

from __future__ import annotations

from pathlib import Path

import pytest

from netopt import paths


def test_netopt_home_overrides_localappdata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``NETOPT_HOME`` 优先于 ``%LOCALAPPDATA%``。"""
    monkeypatch.setenv("NETOPT_HOME", str(tmp_path / "custom"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert paths.app_dir() == tmp_path / "custom"


def test_localappdata_is_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """没有 ``NETOPT_HOME`` 时落到 ``%LOCALAPPDATA%/net-optimizer``。"""
    monkeypatch.delenv("NETOPT_HOME", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert paths.app_dir() == tmp_path / "local" / "net-optimizer"


def test_portable_ignores_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """便携模式指向程序根目录，且优先于 ``NETOPT_HOME``。"""
    monkeypatch.setenv("NETOPT_HOME", str(tmp_path / "custom"))
    expected = Path(paths.__file__).resolve().parent.parent
    assert paths.app_dir(portable=True) == expected


def test_app_dir_does_not_create_dirs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """纯解析不得产生目录（只有 ``ensure_dirs`` 才建）。"""
    target = tmp_path / "not-created"
    monkeypatch.setenv("NETOPT_HOME", str(target))
    assert paths.app_dir() == target
    assert not target.exists()


def test_path_layout(tmp_path: Path) -> None:
    """目录结构：config.toml / state/*.jsonl / logs / raw/<run_id>。"""
    base = tmp_path / "home"
    assert paths.config_path(base) == base / "config.toml"
    assert paths.state_dir(base) == base / "state"
    assert paths.history_path(base) == base / "state" / "history.jsonl"
    assert paths.journal_path(base) == base / "state" / "changes.jsonl"
    assert paths.logs_dir(base) == base / "logs"
    assert paths.raw_dir(base) == base / "raw"
    assert paths.raw_dir(base, run_id="run-1") == base / "raw" / "run-1"


def test_helpers_follow_netopt_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """不传 base 时，各路径函数沿用 ``NETOPT_HOME``。"""
    root = tmp_path / "home"
    monkeypatch.setenv("NETOPT_HOME", str(root))
    assert paths.journal_path() == root / "state" / "changes.jsonl"
    assert paths.history_path() == root / "state" / "history.jsonl"
    assert paths.logs_dir() == root / "logs"
    assert paths.raw_dir(run_id="r1") == root / "raw" / "r1"


def test_ensure_dirs_is_idempotent(tmp_path: Path) -> None:
    """建目录可重复调用；只建 state/logs/raw，不建 config.toml。"""
    base = tmp_path / "fresh" / "home"
    assert paths.ensure_dirs(base) == base
    for child in ("state", "logs", "raw"):
        assert (base / child).is_dir()
    assert not (base / "config.toml").exists()
    # 第二次调用不应报错，也不应多出目录。
    assert paths.ensure_dirs(base) == base
    assert sorted(p.name for p in base.iterdir()) == ["logs", "raw", "state"]


def test_raw_dir_rejects_path_traversal(tmp_path: Path) -> None:
    """``run_id`` 只能是单级目录名。"""
    for bad in ("", ".", "..", "a/b", "a\\b"):
        with pytest.raises(ValueError):
            paths.raw_dir(tmp_path, run_id=bad)
