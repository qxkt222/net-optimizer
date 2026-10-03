# -*- coding: utf-8 -*-
"""GUI 入口测试：D7（``\\r`` 覆盖逻辑）回归、D14（去重接线）、还原 DNS 按钮。

用**隐藏的 Tk 窗口**（``withdraw()``）跑，不弹窗、不抢焦点；环境无法创建 Tk
（无显示器）时用 ``pytest.skip`` 优雅跳过，不会变成假绿。

D7 回归的判据：把 ``gui.App._out`` 里的删除区间改回旧实现
``self.text.delete("insert-1c lineend", "end-1c")``，本文件的
``test_cr_tick_overwrites_same_line`` 与 ``test_cr_replaces_only_last_line``
必须变红（已人工确认）。
"""

from __future__ import annotations

import contextlib

import pytest

from netopt import fix, platform, state

gui = pytest.importorskip("gui", reason="GUI 测试需要 tkinter；无法导入时明确跳过")


@pytest.fixture
def gui_app():
    """隐藏的 App 实例；创建失败（无显示器等）时跳过而不是失败。

    本机（Python 3.13）的 Tcl/Tk 库**偶发**加载失败——新建 ``tk.Tk()`` 时
    约 5% 概率抛 ``TclError``（``invalid command name "tcl_findLibrary"`` 或
    ``Can't find a usable init.tcl``），与代码无关，属环境抖动。所以这里重试几次；
    重试仍失败才 skip（真·无显示器环境不会因为重试而变成假绿）。
    """
    app = None
    last_error: Exception | None = None
    for _ in range(5):
        try:
            app = gui.App()
            break
        except gui.tk.TclError as exc:
            last_error = exc
    if app is None:
        pytest.skip(f"无法创建 Tk 窗口（无显示器 / Tcl 库不可用）: {last_error}")
    app.withdraw()
    # 清掉启动横幅，让断言从空文本开始（disabled 状态下的 delete 会被 Tk 忽略）
    app.text.config(state="normal")
    app.text.delete("1.0", "end")
    app.text.config(state="disabled")
    app._cur_tag = None
    try:
        yield app
    finally:
        with contextlib.suppress(gui.tk.TclError):
            app.destroy()


def _text(app) -> str:
    return app.text.get("1.0", "end-1c")


def _find_button(widget, text):
    for child in widget.winfo_children():
        if isinstance(child, gui.ttk.Button) and child.cget("text") == text:
            return child
        found = _find_button(child, text)
        if found is not None:
            return found
    return None


# ---------------------------------------------------------------------------
# D7：\r 必须覆盖当前行，而不是追加
# ---------------------------------------------------------------------------
def test_cr_tick_overwrites_same_line(gui_app):
    """监控的每次 tick 都带 ``\\r``，最终只能剩最后一次的内容（D7 核心）。"""
    gui_app._out("line1\nline2\n")
    for i in range(1, 4):
        gui_app._out(f"\rTICK-{i}")

    assert _text(gui_app) == "line1\nline2\nTICK-3"


def test_cr_replaces_only_last_line(gui_app):
    """覆盖的是当前行：前面已经换行的内容不能被回退掉（D7）。"""
    gui_app._out("aaa\nbbb\nccc")
    gui_app._out("\rX")

    assert _text(gui_app) == "aaa\nbbb\nX"


def test_cr_after_newline_keeps_history(gui_app):
    """上一次 tick 后普通输出照常换行累计，下一次 tick 只覆盖自己那行。"""
    gui_app._out("\rA")
    gui_app._out("\n")
    gui_app._out("\rB")

    assert _text(gui_app) == "A\nB"


# ---------------------------------------------------------------------------
# ANSI 标签
# ---------------------------------------------------------------------------
def test_bold_ansi_does_not_inherit_previous_color(gui_app):
    """``\\033[1m`` 之后的文本用 bold 标签，而不是继承上一个颜色。"""
    gui_app._out("\033[93m黄\033[1m粗\033[0m默认")

    idx = gui_app.text.search("粗", "1.0")
    assert idx, "没找到粗体字符"
    tags = gui_app.text.tag_names(idx)
    assert "bold" in tags
    assert "yellow" not in tags


# ---------------------------------------------------------------------------
# D14：清除 / 提权 / 解释器全部走 netopt 统一实现
# ---------------------------------------------------------------------------
def test_clear_button_deletes_logs_and_keeps_dns_backup(gui_app):
    old_log = state.BASE / "log-2020-01-01.log"
    old_log.write_text("x", encoding="utf-8")
    state.DEV_FILE.write_text('{"dev": true}', encoding="utf-8")
    state.DNS_BACKUP_FILE.write_text("{}", encoding="utf-8")

    gui_app._clear()

    assert not old_log.exists()
    assert not state.DEV_FILE.exists()
    assert state.DNS_BACKUP_FILE.exists(), "DNS 备份是 fix dns --restore 的依据，clear 不能删"
    assert "已清除: log-2020-01-01.log" in _text(gui_app)


def test_clear_button_reports_nothing_to_do(gui_app):
    gui_app._clear()
    assert "没有需要清除的文件" in _text(gui_app)


def test_run_admin_builds_console_python_command(gui_app, monkeypatch):
    """提权新窗口：runas + console_python + netoptimizer.py + --wait（D14）。"""
    seen: list[tuple] = []
    monkeypatch.setattr(
        platform,
        "_shell_execute",
        lambda op, exe, params, cwd: seen.append((op, exe, params, cwd)) or 33,
    )

    gui_app._run_admin("fix dns --restore")

    assert len(seen) == 1
    op, exe, params, cwd = seen[0]
    script = state.BASE / "netoptimizer.py"
    assert op == "runas"
    assert exe == platform.console_python()
    assert params == f'"{script}" fix dns --restore --wait'
    assert cwd == str(state.BASE)
    assert "已以管理员身份启动" in _text(gui_app)


def test_run_admin_reports_cancelled_uac(gui_app, monkeypatch):
    monkeypatch.setattr(platform, "_shell_execute", lambda *args: 5)

    gui_app._run_admin("fix tcp")

    assert "提权被取消" in _text(gui_app)


def test_relaunch_admin_uses_platform_elevate(gui_app, monkeypatch):
    seen: list[list[str]] = []
    monkeypatch.setattr(platform, "is_admin", lambda: False)
    monkeypatch.setattr(platform, "elevate", lambda args, **kw: seen.append(list(args)) or True)

    gui_app._relaunch_admin()

    assert seen == [[]], "重启 GUI 由 platform.elevate 接管（它自己解析 sys.argv[0]）"
    assert "已以管理员身份启动新窗口" in _text(gui_app)


# ---------------------------------------------------------------------------
# 按钮：还原 DNS
# ---------------------------------------------------------------------------
def test_restore_dns_button_exists(gui_app):
    assert _find_button(gui_app, "还原 DNS") is not None


def test_restore_dns_button_calls_fix_with_restore(gui_app, monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(platform, "is_admin", lambda: True)
    monkeypatch.setattr(
        fix, "cmd_fix", lambda what="all", *, restore=False: calls.append((what, restore))
    )
    monkeypatch.setattr(gui_app, "_run", lambda fn, *args: fn(*args))  # 同步执行，避免线程

    _find_button(gui_app, "还原 DNS").invoke()

    assert calls == [("dns", True)]


def test_repair_dns_button_still_calls_plain_fix(gui_app, monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(platform, "is_admin", lambda: True)
    monkeypatch.setattr(
        fix, "cmd_fix", lambda what="all", *, restore=False: calls.append((what, restore))
    )
    monkeypatch.setattr(gui_app, "_run", lambda fn, *args: fn(*args))

    _find_button(gui_app, "修复 DNS").invoke()

    assert calls == [("dns", False)]


def test_restore_dns_button_elevates_when_not_admin(gui_app, monkeypatch):
    elevated: list[str] = []
    monkeypatch.setattr(platform, "is_admin", lambda: False)
    monkeypatch.setattr(gui_app, "_run_admin", lambda cmd: elevated.append(cmd))

    _find_button(gui_app, "还原 DNS").invoke()

    assert elevated == ["fix dns --restore"]
