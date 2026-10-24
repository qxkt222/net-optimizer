# -*- coding: utf-8 -*-
"""CLI 补齐测试：``status --json``、全局 ``--portable``、``config`` 与 ``update``。

这些用例**不探测、不联网、不读写真实配置**：``config.load`` / ``config.save``
与 ``update.check`` 一律 monkeypatch 成替身；``--portable`` 只验证环境变量与
路径解析的结果。
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

import netopt
import netopt.cli as cli
from netopt import config as config_mod
from netopt import update as update_mod
from netopt.commands import status as status_cmd
from netopt.domain import Report, Section

runner = CliRunner()


def _report() -> Report:
    """最小 status 报告（不探测）。"""
    return Report(
        command="status",
        started_at=datetime.now(UTC),
        duration_ms=1,
        environment={"admin": False},
        sections=[Section(id="gateway", title="网关")],
        findings=[],
        errors=[],
    )


def _info(
    *,
    current: str = "2.0.0",
    latest: str | None = "2.1.0",
    url: str | None = "https://example.com/release",
    available: bool = True,
    error: str | None = None,
) -> update_mod.UpdateInfo:
    """构造一次更新检查结果。"""
    return update_mod.UpdateInfo(
        current=current,
        latest=latest,
        url=url,
        available=available,
        error=error,
    )


# ===========================================================================
# status：本地 --json
# ===========================================================================
def test_status_accepts_json_after_subcommand(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _report()
    monkeypatch.setattr(status_cmd, "build_status_report", lambda: report)

    result = runner.invoke(cli.app, ["status", "--json"])

    assert result.exit_code == 0
    assert result.stdout.startswith("{")
    payload = json.loads(result.stdout)  # 整段 stdout 可解析 → 没有夹带提示行
    assert payload["command"] == "status"
    assert payload["sections"][0]["id"] == "gateway"


# ===========================================================================
# 全局 --portable
# ===========================================================================
def test_portable_sets_netopt_home_to_program_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETOPT_HOME", "C:/sentinel-home")
    root = Path(netopt.__file__).resolve().parent.parent

    result = runner.invoke(cli.app, ["--portable", "config", "path"])

    assert result.exit_code == 0
    assert Path(result.stdout.strip()) == root / "config.toml"
    assert os.environ["NETOPT_HOME"] == str(root), "--portable 必须在命令执行前覆盖 NETOPT_HOME"


def test_config_path_respects_netopt_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NETOPT_HOME", str(tmp_path))

    result = runner.invoke(cli.app, ["config", "path"])

    assert result.exit_code == 0
    assert Path(result.stdout.strip()) == tmp_path / "config.toml"


# ===========================================================================
# config get
# ===========================================================================
def test_config_get_json_outputs_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod, "load", lambda: config_mod.Settings(language="en"))

    result = runner.invoke(cli.app, ["config", "get", "--json"])

    assert result.exit_code == 0
    assert result.stdout.startswith("{")
    payload = json.loads(result.stdout)
    assert payload["language"] == "en"
    assert payload["policy"]["wan"]["warn"] == 100
    assert payload["policy"]["weights"]["gateway"] == 15


def test_config_get_global_json_also_applies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod, "load", lambda: config_mod.Settings(language="en"))

    result = runner.invoke(cli.app, ["--json", "config", "get"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["language"] == "en"


def test_config_get_text_uses_dotted_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod, "load", lambda: config_mod.Settings(language="en"))

    result = runner.invoke(cli.app, ["config", "get"])

    assert result.exit_code == 0
    assert 'language = "en"' in result.stdout
    assert "policy.wan.warn = 100" in result.stdout
    assert "policy.gateway.good = 5" in result.stdout


def test_config_get_load_failure_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> config_mod.Settings:
        raise ValueError("未知配置项: foo")

    monkeypatch.setattr(config_mod, "load", boom)

    result = runner.invoke(cli.app, ["config", "get", "--json"])

    assert result.exit_code == 1
    assert "配置错误" in result.stderr
    assert "未知配置项: foo" in result.stderr
    assert result.stdout == "", "配置错误不得污染 stdout"


# ===========================================================================
# config set
# ===========================================================================
def _patch_config(
    monkeypatch: pytest.MonkeyPatch,
    settings: config_mod.Settings | None = None,
) -> list[config_mod.Settings]:
    """把 load 固定成给定配置、save 换成记录器，返回保存列表。"""
    saved: list[config_mod.Settings] = []
    monkeypatch.setattr(
        config_mod,
        "load",
        lambda: settings if settings is not None else config_mod.Settings(),
    )
    monkeypatch.setattr(config_mod, "save", lambda value: saved.append(value))
    return saved


def test_config_set_nested_key_persists_validated_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved = _patch_config(monkeypatch)

    result = runner.invoke(cli.app, ["config", "set", "policy.wan.warn", "120"])

    assert result.exit_code == 0
    assert "已设置 policy.wan.warn = 120" in result.stdout
    assert len(saved) == 1
    updated = saved[0]
    assert updated.policy.wan.warn == 120
    assert updated.policy.wan.good == 30, "未修改的同组字段必须保留"
    assert updated.policy.wan.poor == 150


def test_config_set_top_level_scalar(monkeypatch: pytest.MonkeyPatch) -> None:
    saved = _patch_config(monkeypatch)

    result = runner.invoke(cli.app, ["config", "set", "language", "en-US"])

    assert result.exit_code == 0
    assert saved[0].language == "en-US"


def test_config_set_list_value_accepts_json(monkeypatch: pytest.MonkeyPatch) -> None:
    saved = _patch_config(monkeypatch)

    result = runner.invoke(
        cli.app,
        ["config", "set", "ping_targets", '["1.1.1.1", "8.8.8.8"]'],
    )

    assert result.exit_code == 0
    assert saved[0].ping_targets == ["1.1.1.1", "8.8.8.8"]


def test_config_set_unknown_key_exits_1_without_saving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved = _patch_config(monkeypatch)

    result = runner.invoke(cli.app, ["config", "set", "policy.wan.nope", "1"])

    assert result.exit_code == 1
    assert "未知配置项: policy.wan.nope" in result.stderr
    assert saved == []


def test_config_set_scalar_prefix_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    """把标量当分组（``language.x``）同样是非法键。"""
    saved = _patch_config(monkeypatch)

    result = runner.invoke(cli.app, ["config", "set", "language.code", "zh"])

    assert result.exit_code == 1
    assert "未知配置项" in result.stderr
    assert saved == []


def test_config_set_unparsable_value_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    saved = _patch_config(monkeypatch)

    result = runner.invoke(cli.app, ["config", "set", "policy.wan.warn", "很快"])

    assert result.exit_code == 1
    assert "配置错误" in result.stderr
    assert saved == []


def test_config_set_inconsistent_threshold_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    """单个值类型合法但破坏 Band 的 good < warn < poor 约束 → 校验失败。"""
    saved = _patch_config(monkeypatch)

    result = runner.invoke(cli.app, ["config", "set", "policy.wan.warn", "1"])

    assert result.exit_code == 1
    assert "配置错误" in result.stderr
    assert saved == []


# ===========================================================================
# update
# ===========================================================================
def test_update_json_outputs_update_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_mod, "check", lambda: _info())

    result = runner.invoke(cli.app, ["update", "--json"])

    assert result.exit_code == 0
    assert result.stdout.startswith("{")
    payload = json.loads(result.stdout)
    assert payload == {
        "current": "2.0.0",
        "latest": "2.1.0",
        "url": "https://example.com/release",
        "available": True,
        "error": None,
    }


def test_update_global_json_also_applies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_mod, "check", lambda: _info())

    result = runner.invoke(cli.app, ["--json", "update"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["latest"] == "2.1.0"


def test_update_text_shows_current_latest_and_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_mod, "check", lambda: _info())

    result = runner.invoke(cli.app, ["update"])

    assert result.exit_code == 0
    assert "当前版本：2.0.0" in result.stdout
    assert "最新版本：2.1.0" in result.stdout
    assert "发现新版本" in result.stdout
    assert "https://example.com/release" in result.stdout


def test_update_text_when_already_latest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update_mod,
        "check",
        lambda: _info(latest="2.0.0", url=None, available=False),
    )

    result = runner.invoke(cli.app, ["update"])

    assert result.exit_code == 0
    assert "已是最新版本" in result.stdout
    assert "发现新版本" not in result.stdout


def test_update_check_failure_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update_mod,
        "check",
        lambda: _info(latest=None, url=None, available=False, error="网络不可达"),
    )

    result = runner.invoke(cli.app, ["update", "--json"])

    assert result.exit_code == 0, "检查失败默认仍是 0（只提示，不报错）"
    payload = json.loads(result.stdout)
    assert payload["error"] == "网络不可达"
    assert payload["latest"] is None


def test_update_check_failure_text_shows_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update_mod,
        "check",
        lambda: _info(latest=None, url=None, available=False, error="网络不可达"),
    )

    result = runner.invoke(cli.app, ["update"])

    assert result.exit_code == 0
    assert "检查失败：网络不可达" in result.stdout


def test_update_strict_failure_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update_mod,
        "check",
        lambda: _info(latest=None, url=None, available=False, error="网络不可达"),
    )

    result = runner.invoke(cli.app, ["update", "--strict"])

    assert result.exit_code == 2
    assert "检查失败：网络不可达" in result.stdout


def test_update_strict_success_exits_0(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_mod, "check", lambda: _info())

    result = runner.invoke(cli.app, ["update", "--strict"])

    assert result.exit_code == 0
