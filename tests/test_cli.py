# -*- coding: utf-8 -*-
"""CLI 入口（``netoptimizer.py``）测试：命令分发 / 提权 / dev / clear 接线。

**绝不真实执行命令**：``conftest.py`` 的 autouse 夹具会拦截真实子进程；
本文件再进一步，把所有 ``cmd_*`` 换成记录器，双保险。
"""

from __future__ import annotations

import json
import sys
import time

import pytest

import netoptimizer
from netopt import diag, fix, health, platform, state

#: BRIEF §2.4 冻结的 CLI 命令字面量，一个都不能少
ALL_COMMANDS = [
    "status",
    "full",
    "auto",
    "ping",
    "dns",
    "http",
    "speed",
    "trace",
    "wifi",
    "fix",
    "monitor",
    "dev",
    "health",
    "admin",
    "clear",
    "help",
]


@pytest.fixture
def dispatched(monkeypatch):
    """把所有 ``cmd_*`` 换成记录器；返回 ``[(name, args, kwargs), ...]``。"""
    calls: list[tuple[str, tuple, dict]] = []

    def recorder(name):
        def _rec(*args, **kwargs):
            calls.append((name, args, kwargs))

        return _rec

    modules = (
        (
            diag,
            [
                "cmd_status",
                "cmd_full",
                "cmd_ping",
                "cmd_dns",
                "cmd_http",
                "cmd_speed",
                "cmd_trace",
                "cmd_wifi",
                "cmd_monitor",
            ],
        ),
        (fix, ["cmd_fix", "cmd_auto"]),
        (health, ["cmd_health"]),
    )
    for module, names in modules:
        short = module.__name__.rsplit(".", 1)[-1]
        for attr in names:
            monkeypatch.setattr(module, attr, recorder(f"{short}.{attr}"))
    return calls


@pytest.fixture
def as_admin(monkeypatch):
    """默认让 CLI 认为自己是管理员，从而直接分发而不是提权。"""
    monkeypatch.setattr(platform, "is_admin", lambda: True)


# ---------------------------------------------------------------------------
# help / 未知命令
# ---------------------------------------------------------------------------
def test_help_lists_every_frozen_command(capsys):
    assert netoptimizer.main(["help"]) == 0

    out = capsys.readouterr().out
    for command in ALL_COMMANDS:
        assert command in out, f"help 里缺少命令: {command}"
    assert "fix dns --restore" in out, "新增的还原 DNS 必须在帮助里出现"


def test_no_args_prints_help(capsys):
    netoptimizer.main([])
    assert "用法: python netoptimizer.py <命令> [参数]" in capsys.readouterr().out


def test_wait_flag_is_stripped_before_dispatch(dispatched, as_admin):
    netoptimizer.main(["status", "--wait"])
    assert dispatched == [("diag.cmd_status", (), {})]


def test_unknown_command_prints_hint(capsys):
    assert netoptimizer.main(["nope"]) == 0
    out = capsys.readouterr().out
    assert "未知命令: nope" in out
    assert "status" in out  # 顺带打印帮助


# ---------------------------------------------------------------------------
# 分发
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["status"], ("diag.cmd_status", (), {})),
        (["full"], ("diag.cmd_full", (), {})),
        (["auto"], ("fix.cmd_auto", (), {})),
        (["ping"], ("diag.cmd_ping", (None,), {})),
        (["ping", "1.1.1.1"], ("diag.cmd_ping", ("1.1.1.1",), {})),
        (["dns"], ("diag.cmd_dns", (), {})),
        (["http"], ("diag.cmd_http", (), {})),
        (["speed"], ("diag.cmd_speed", (), {})),
        (["trace"], ("diag.cmd_trace", (None,), {})),
        (["trace", "8.8.8.8"], ("diag.cmd_trace", ("8.8.8.8",), {})),
        (["wifi"], ("diag.cmd_wifi", (), {})),
        (["health"], ("health.cmd_health", (), {})),
        (["monitor"], ("diag.cmd_monitor", (60,), {})),
        (["monitor", "10"], ("diag.cmd_monitor", (10,), {})),
        (["monitor", "3"], ("diag.cmd_monitor", (5,), {})),  # 下限 5
        (["monitor", "9999"], ("diag.cmd_monitor", (600,), {})),  # 上限 600
        (["monitor", "abc"], ("diag.cmd_monitor", (60,), {})),  # 非数字 → 默认
        (["fix"], ("fix.cmd_fix", ("all",), {"restore": False})),
        (["fix", "dns"], ("fix.cmd_fix", ("dns",), {"restore": False})),
        (["fix", "tcp"], ("fix.cmd_fix", ("tcp",), {"restore": False})),
        (["fix", "power"], ("fix.cmd_fix", ("power",), {"restore": False})),
        # 新增：fix dns --restore
        (["fix", "dns", "--restore"], ("fix.cmd_fix", ("dns",), {"restore": True})),
    ],
)
def test_command_dispatch(dispatched, as_admin, argv, expected):
    assert netoptimizer.main(argv) == 0
    assert dispatched == [expected]


# ---------------------------------------------------------------------------
# 管理员提权（NEED_ADMIN）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("command", ["fix", "auto", "dev"])
def test_need_admin_commands_elevate_when_not_admin(dispatched, monkeypatch, capsys, command):
    elevated: list[list[str]] = []
    monkeypatch.setattr(platform, "is_admin", lambda: False)
    monkeypatch.setattr(platform, "elevate", lambda args, **kw: elevated.append(list(args)) or True)

    assert netoptimizer.main([command]) == 0

    assert elevated == [[command, "--wait"]], "非管理员时必须原样提权并带 --wait"
    assert dispatched == [], "提权后本进程不应再执行命令"
    assert "需要管理员权限" in capsys.readouterr().out


def test_need_admin_keeps_original_arguments(dispatched, monkeypatch):
    elevated: list[list[str]] = []
    monkeypatch.setattr(platform, "is_admin", lambda: False)
    monkeypatch.setattr(platform, "elevate", lambda args, **kw: elevated.append(list(args)) or True)

    netoptimizer.main(["fix", "dns", "--restore"])

    assert elevated == [["fix", "dns", "--restore", "--wait"]]
    assert dispatched == []


def test_elevate_cancelled_is_reported(dispatched, monkeypatch, capsys):
    monkeypatch.setattr(platform, "is_admin", lambda: False)
    monkeypatch.setattr(platform, "elevate", lambda args, **kw: False)

    netoptimizer.main(["fix"])

    assert "提权被取消" in capsys.readouterr().out
    assert dispatched == []


def test_admin_command_relaunches_with_current_argv(monkeypatch, capsys):
    elevated: list[list[str]] = []
    monkeypatch.setattr(sys, "argv", ["netoptimizer.py", "admin"])
    monkeypatch.setattr(platform, "elevate", lambda args, **kw: elevated.append(list(args)) or True)

    netoptimizer.main(["admin"])

    assert elevated == [["admin"]]
    assert "正在以管理员身份重新启动" in capsys.readouterr().out


def test_admin_command_reports_failure(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["netoptimizer.py", "admin"])
    monkeypatch.setattr(platform, "elevate", lambda args, **kw: False)

    netoptimizer.main(["admin"])

    assert "提权被取消或失败" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# dev / clear
# ---------------------------------------------------------------------------
def test_dev_on_writes_dev_file(dispatched, as_admin):
    assert netoptimizer.main(["dev", "on"]) == 0

    assert state.DEV_FILE.exists()
    assert json.loads(state.DEV_FILE.read_text(encoding="utf-8")) == {"dev": True}
    assert state.DEV_ON is True, "开启后本进程应立即生效"


def test_dev_off_removes_dev_file(dispatched, as_admin):
    state.DEV_FILE.write_text('{"dev": true}', encoding="utf-8")

    assert netoptimizer.main(["dev", "off"]) == 0

    assert not state.DEV_FILE.exists()
    assert state.DEV_ON is False


def test_dev_without_valid_mode_prints_usage(dispatched, as_admin, capsys):
    netoptimizer.main(["dev"])
    assert "用法: dev on|off" in capsys.readouterr().out


def test_clear_routes_to_state_clear(monkeypatch, capsys):
    monkeypatch.setattr(state, "clear", lambda: ["log-2026-10-03.log", "history.json"])

    netoptimizer.main(["clear"])

    out = capsys.readouterr().out
    assert "已清除" in out
    assert "log-2026-10-03.log" in out
    assert "history.json" in out


def test_clear_on_empty_base_reports_nothing_to_do(capsys):
    # 直接调 cmd_clear：main() 会先写一行「运行: clear」日志，BASE 不会是空的
    netoptimizer.cmd_clear()
    assert "没有需要清除的文件" in capsys.readouterr().out


def test_clear_removes_state_but_keeps_dns_backup():
    log = state.BASE / f"log-{time.strftime('%Y-%m-%d')}.log"
    log.write_text("旧日志", encoding="utf-8")
    state.DEV_FILE.write_text('{"dev": true}', encoding="utf-8")
    state.hist_add({"cmd": "x"})
    state.DNS_BACKUP_FILE.write_text("{}", encoding="utf-8")

    netoptimizer.main(["clear"])

    assert not state.HISTORY_FILE.exists()
    assert not state.DEV_FILE.exists()
    assert state.DNS_BACKUP_FILE.exists(), "DNS 备份是 fix dns --restore 的依据，clear 不能删"
    # clear 之后会写一行「clear 完成」日志，但旧内容必须已被清掉
    assert "旧日志" not in log.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 异常处理
# ---------------------------------------------------------------------------
def test_command_exception_is_reported_and_swallowed(dispatched, as_admin, monkeypatch, capsys):
    def boom():
        raise RuntimeError("炸了")

    monkeypatch.setattr(diag, "cmd_status", boom)

    assert netoptimizer.main(["status"]) == 0
    assert "出错: 炸了" in capsys.readouterr().out


def test_keyboard_interrupt_is_reported(dispatched, as_admin, monkeypatch, capsys):
    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr(diag, "cmd_full", interrupt)

    assert netoptimizer.main(["full"]) == 0
    assert "已中断" in capsys.readouterr().out
