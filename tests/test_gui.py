# -*- coding: utf-8 -*-
"""GUI 入口测试：D7（``\\r`` 覆盖逻辑）回归、D14（去重接线）、T5.1 全量迁移。

用**隐藏的 Tk 窗口**（``withdraw()``）跑，不弹窗、不抢焦点；环境无法创建 Tk
（无显示器）时用 ``pytest.skip`` 优雅跳过，不会变成假绿。

D7 回归的判据：把 ``gui.App._out`` 里的删除区间改回旧实现
``self.text.delete("insert-1c lineend", "end-1c")``，本文件的
``test_cr_tick_overwrites_same_line`` 与 ``test_cr_replaces_only_last_line``
必须变红（已人工确认）。

T5.1 回归的判据：``gui`` 模块不再有 ``Redirector`` / ``ANSI_RE`` / ``COLOR_TAGS``；
所有一次性按钮都在工作线程构建 Report、主线程渲染；修复按钮走
``netopt.commands.fix``，还原 DNS 走 ``undo_last(kind="dns")``。
"""

from __future__ import annotations

import contextlib
import gc
import sys
import threading
import time
from datetime import UTC, datetime

import pytest

from netopt import platform, state
from netopt.commands import dns as cmd_dns
from netopt.commands import fix as cmd_fix
from netopt.commands import health as cmd_health
from netopt.commands import http as cmd_http
from netopt.commands import ping as cmd_ping
from netopt.commands import speed as cmd_speed
from netopt.commands import status as cmd_status
from netopt.commands import trace as cmd_trace
from netopt.commands import undo as cmd_undo
from netopt.commands import wifi as cmd_wifi
from netopt.commands.fix import FixKind, FixPlan, FixResult, FixStep
from netopt.commands.undo import UndoResult
from netopt.domain.report import Finding, Report, Section, Severity
from netopt.models import PingStat

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
    try:
        yield app
    finally:
        with contextlib.suppress(gui.tk.TclError):
            app.destroy()
        # Tk 对象只能在主线程回收：若留给下一次测试的工作线程 GC，释放 Tcl
        # 对象会在 Windows 上触发 fatal exception 0x80000003（栈在 GC）。
        # 这里先删掉引用，再在主线程强制回收，避免跨线程析构。
        del app
        gc.collect()


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


def _pump_until_idle(app, timeout: float = 5.0) -> bool:
    """反复泵 ``_poll`` 直到 worker 放下 ``__done__``（``busy`` 复位）或超时。

    ``_poll`` 本身会 ``after(80, ...)`` 排下一次；测试里没有 mainloop，
    所以直接调用它来消费队列，不能只泵一次——工作线程还没跑完时队列是空的。
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app._poll()
        if not app.busy:
            return True
        time.sleep(0.01)
    return False


def _fixed_status_report() -> Report:
    """固定 Report：1 个 section、1 条 finding（T1.8 断言基准）。"""
    finding = Finding(
        code="STATUS_GUI_TEST",
        severity=Severity.info,
        title="快速诊断固定结论",
        detail="测试用固定内容",
        advice=["无需处理"],
    )
    return Report(
        command="status",
        started_at=datetime(2026, 10, 24, tzinfo=UTC),
        duration_ms=1,
        environment={},
        sections=[Section(id="summary", title="概览", findings=[finding])],
        findings=[],
        errors=[],
    )


def _empty_plan() -> FixPlan:
    return FixPlan(steps=[], findings=[])


def _fix_result(kind: FixKind = FixKind.dns) -> FixResult:
    return FixResult(kind=kind, applied=[], failed=[], skipped=[], findings=[])


def _ping_stat(avg_ms: float | None, max_ms: float | None, *, replies: int = 1) -> PingStat:
    return PingStat(
        target="www.baidu.com",
        avg_ms=avg_ms,
        max_ms=max_ms,
        loss_pct=0.0 if replies else 100.0,
        replies=replies,
    )


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
# T5.1：ANSI 解析与 stdout 重定向已删除
# ---------------------------------------------------------------------------
def test_gui_module_has_no_stdout_redirector_or_ansi():
    """``Redirector`` / ``ANSI_RE`` / ``COLOR_TAGS`` 必须从 gui 模块彻底消失。"""
    assert not hasattr(gui, "Redirector")
    assert not hasattr(gui, "ANSI_RE")
    assert not hasattr(gui, "COLOR_TAGS")
    assert not hasattr(gui, "diag"), "GUI 不得再依赖 v1 diag 命令"


def test_out_keeps_ansi_text_without_parsing(gui_app):
    """ANSI 转义码原样插入；不再映射成 tk 颜色标签（旧行为已删除）。"""
    gui_app._out("\033[93m黄\033[1m粗\033[0m默认")

    assert _text(gui_app) == "\033[93m黄\033[1m粗\033[0m默认"
    idx = gui_app.text.search("粗", "1.0")
    assert idx, "没找到粗体字符"
    tags = gui_app.text.tag_names(idx)
    assert "bold" not in tags
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
# 一次性命令按钮：每个 builder 恰好调用一次
# ---------------------------------------------------------------------------
ONE_SHOT_BUILDERS = [
    pytest.param(cmd_health, "build_health_report", "健康评分", id="health"),
    pytest.param(cmd_speed, "build_speed_report", "带宽测速", id="speed"),
    pytest.param(cmd_ping, "build_ping_report", "延迟测试", id="ping"),
    pytest.param(cmd_dns, "build_dns_report", "DNS 基准", id="dns"),
    pytest.param(cmd_http, "build_http_report", "HTTP 测试", id="http"),
    pytest.param(cmd_trace, "build_trace_report", "路由追踪", id="trace"),
    pytest.param(cmd_wifi, "build_wifi_report", "WiFi 检查", id="wifi"),
]


@pytest.mark.parametrize(("module", "attr", "button"), ONE_SHOT_BUILDERS)
def test_one_shot_button_calls_its_builder_once(gui_app, monkeypatch, module, attr, button):
    calls: list[int] = []

    def fake_builder() -> Report:
        calls.append(1)
        return _fixed_status_report()

    monkeypatch.setattr(module, attr, fake_builder)
    monkeypatch.setattr(gui, "render_plain", lambda report: "报告正文")

    widget = _find_button(gui_app, button)
    assert widget is not None, f"找不到按钮 {button}"
    widget.invoke()

    assert _pump_until_idle(gui_app), f"{button} worker 未在超时内结束"
    assert len(calls) == 1, f"{button} 的 builder 必须恰好调用一次"
    assert "报告正文" in _text(gui_app)


def test_status_button_calls_command_builder_once(gui_app, monkeypatch):
    """快速诊断的薄包装在调用时解析命令层 builder（可被模块级 patch 命中）。"""
    calls: list[int] = []

    def fake_builder() -> Report:
        calls.append(1)
        return _fixed_status_report()

    monkeypatch.setattr(cmd_status, "build_status_report", fake_builder)
    monkeypatch.setattr(gui, "render_plain", lambda report: "状态报告")

    _find_button(gui_app, "快速诊断").invoke()

    assert _pump_until_idle(gui_app), "快速诊断 worker 未在超时内结束"
    assert len(calls) == 1
    assert "状态报告" in _text(gui_app)


def test_full_diagnose_button_calls_builder_once(gui_app, monkeypatch):
    """全面诊断消费 ``netopt.commands.full.build_full_report``（惰性导入）。"""
    full_mod = pytest.importorskip(
        "netopt.commands.full", reason="并行任务 netopt.commands.full 尚未落地"
    )
    calls: list[int] = []

    def fake_builder() -> Report:
        calls.append(1)
        return _fixed_status_report()

    monkeypatch.setattr(full_mod, "build_full_report", fake_builder)
    monkeypatch.setattr(gui, "render_plain", lambda report: "全面报告")

    _find_button(gui_app, "全面诊断").invoke()

    assert _pump_until_idle(gui_app), "全面诊断 worker 未在超时内结束"
    assert len(calls) == 1
    assert "全面报告" in _text(gui_app)


def test_busy_rejects_second_task(gui_app, monkeypatch):
    gui_app.busy = True
    calls: list[int] = []
    monkeypatch.setattr(cmd_health, "build_health_report", lambda: calls.append(1))

    _find_button(gui_app, "健康评分").invoke()

    assert calls == []
    assert "有任务正在运行" in _text(gui_app)


# ---------------------------------------------------------------------------
# 延迟监控：GUI 内循环 probes.ping，stop_event 可停止
# ---------------------------------------------------------------------------
def test_monitor_loop_stops_on_stop_event_without_sleeping():
    """假 ping 在第 3 次后置位 stop_event；interval=0 保证不等待。"""
    stop_event = threading.Event()
    calls: list[tuple] = []

    def fake_ping(target, count, timeout_ms):
        calls.append((target, count, timeout_ms))
        if len(calls) == 3:
            stop_event.set()
        return _ping_stat(10.0 + len(calls), 20.0 + len(calls))

    lines: list[str] = []
    stats = gui._monitor_loop(
        lines.append,
        stop_event,
        count=60,
        interval=0.0,
        ping=fake_ping,
    )

    assert len(calls) == 3, "stop_event 置位后必须立即停止，不能再 ping"
    assert all(call == ("www.baidu.com", 1, 1000) for call in calls)
    assert len(stats) == 3
    assert len(lines) == 4, "3 个 tick + 1 行汇总"
    assert "延迟监控汇总" in lines[-1]
    assert "成功 3 次" in lines[-1]


def test_monitor_summary_reports_average_max_and_loss():
    stats = [
        _ping_stat(10.0, 20.0),
        _ping_stat(30.0, 40.0),
        _ping_stat(None, None, replies=0),
    ]

    text = gui._monitor_summary(stats)

    assert "样本 3 次" in text
    assert "成功 2 次" in text
    assert "丢包率 33.3%" in text
    assert "平均 20.0 ms" in text
    assert "最大 40.0 ms" in text


def test_monitor_button_runs_gui_loop_and_queues_lines(gui_app, monkeypatch):
    """按钮把 GUI 自己的 stop_event 交给循环，tick 文本进文本框。"""
    seen: list[threading.Event] = []

    def fake_loop(put, stop_event, **kwargs):
        seen.append(stop_event)
        put("tick-1")
        return []

    monkeypatch.setattr(gui, "_monitor_loop", fake_loop)

    _find_button(gui_app, "延迟监控").invoke()

    assert _pump_until_idle(gui_app), "监控 worker 未在超时内结束"
    assert seen == [gui_app.stop_event]
    assert "tick-1" in _text(gui_app)


# ---------------------------------------------------------------------------
# 修复按钮：plan_fix / apply_fix / undo_last
# ---------------------------------------------------------------------------
def test_fix_summary_lists_one_line_per_step():
    step = FixStep(
        description="设置 DNS 223.5.5.5",
        kind="dns",
        target="WLAN",
        before={},
        after={},
        undo=[],
    )
    plan = FixPlan(steps=[step], findings=[])
    result = FixResult(kind=FixKind.dns, applied=["change-1"], failed=[], skipped=[], findings=[])

    text = gui._format_fix_summary("修复 dns", plan, result)

    assert "设置 DNS 223.5.5.5" in text
    assert "成功 1 项" in text


def test_repair_dns_button_calls_plan_and_apply_fix(gui_app, monkeypatch):
    calls: list[tuple[str, FixKind]] = []
    monkeypatch.setattr(platform, "is_admin", lambda: True)
    monkeypatch.setattr(
        cmd_fix, "plan_fix", lambda kind, **kw: calls.append(("plan", kind)) or _empty_plan()
    )
    monkeypatch.setattr(
        cmd_fix, "apply_fix", lambda kind, **kw: calls.append(("apply", kind)) or _fix_result(kind)
    )

    _find_button(gui_app, "修复 DNS").invoke()

    assert _pump_until_idle(gui_app), "修复 worker 未在超时内结束"
    assert calls == [("plan", FixKind.dns), ("apply", FixKind.dns)]
    assert "修复 dns" in _text(gui_app)


def test_auto_button_applies_fix_all(gui_app, monkeypatch):
    called: list[FixKind] = []
    monkeypatch.setattr(platform, "is_admin", lambda: True)
    monkeypatch.setattr(cmd_fix, "plan_fix", lambda kind, **kw: _empty_plan())
    monkeypatch.setattr(
        cmd_fix, "apply_fix", lambda kind, **kw: called.append(kind) or _fix_result(kind)
    )

    _find_button(gui_app, "一键优化 auto").invoke()

    assert _pump_until_idle(gui_app), "auto worker 未在超时内结束"
    assert called == [FixKind.all]


def test_restore_dns_button_calls_undo_last_kind_dns(gui_app, monkeypatch):
    calls: list[str | None] = []
    monkeypatch.setattr(platform, "is_admin", lambda: True)
    monkeypatch.setattr(
        cmd_undo,
        "undo_last",
        lambda *, kind=None: (
            calls.append(kind)
            or UndoResult(change_id=None, executed=0, failed=[], message="没有可回滚的变更")
        ),
    )

    _find_button(gui_app, "还原 DNS").invoke()

    assert _pump_until_idle(gui_app), "还原 worker 未在超时内结束"
    assert calls == ["dns"]
    assert "没有可回滚的变更" in _text(gui_app)


def test_fix_error_is_shown_and_busy_resets(gui_app, monkeypatch):
    monkeypatch.setattr(platform, "is_admin", lambda: True)
    monkeypatch.setattr(cmd_fix, "plan_fix", lambda kind, **kw: _empty_plan())

    def boom(kind, **kw):
        raise RuntimeError("journal 不可写")

    monkeypatch.setattr(cmd_fix, "apply_fix", boom)

    _find_button(gui_app, "修复 TCP").invoke()

    assert _pump_until_idle(gui_app), "修复 worker 未在超时内结束"
    assert "[错误] journal 不可写" in _text(gui_app)
    assert gui_app.busy is False


def test_restore_dns_button_exists(gui_app):
    assert _find_button(gui_app, "还原 DNS") is not None


def test_restore_dns_button_elevates_when_not_admin(gui_app, monkeypatch):
    elevated: list[str] = []
    monkeypatch.setattr(platform, "is_admin", lambda: False)
    monkeypatch.setattr(gui_app, "_run_admin", lambda cmd: elevated.append(cmd))

    _find_button(gui_app, "还原 DNS").invoke()

    assert elevated == ["fix dns --restore"]


def test_repair_dns_button_elevates_when_not_admin(gui_app, monkeypatch):
    elevated: list[str] = []
    monkeypatch.setattr(platform, "is_admin", lambda: False)
    monkeypatch.setattr(gui_app, "_run_admin", lambda cmd: elevated.append(cmd))

    _find_button(gui_app, "修复 DNS").invoke()

    assert elevated == ["fix dns"]


def test_auto_button_elevates_when_not_admin(gui_app, monkeypatch):
    elevated: list[str] = []
    monkeypatch.setattr(platform, "is_admin", lambda: False)
    monkeypatch.setattr(gui_app, "_run_admin", lambda cmd: elevated.append(cmd))

    _find_button(gui_app, "一键优化 auto").invoke()

    assert elevated == ["auto"]


# ---------------------------------------------------------------------------
# T1.8：「快速诊断」直接消费 Report，不经 stdout 重定向 / ANSI
# ---------------------------------------------------------------------------
def test_quick_diagnose_consumes_report(gui_app, monkeypatch):
    """``_run_status`` 调 build_status_report，再把 render_plain 的结果插进文本框。"""
    built: list[int] = []

    def fake_build() -> Report:
        built.append(1)
        return _fixed_status_report()

    def fake_render(report: Report) -> str:
        finding = report.sections[0].findings[0]
        return f"[渲染] {finding.title}"

    monkeypatch.setattr(gui, "build_status_report", fake_build)
    monkeypatch.setattr(gui, "render_plain", fake_render)

    gui_app._run_status()

    assert _pump_until_idle(gui_app), "worker 未在超时内结束"
    assert built == [1], "build_status_report 必须恰好调用一次"
    assert "快速诊断固定结论" in _text(gui_app)
    assert "完成" in _text(gui_app), "完成分隔线行为必须与其他按钮一致"
    assert gui_app.busy is False


def test_quick_diagnose_does_not_touch_stdout(gui_app, monkeypatch):
    """这条路径不得替换 ``sys.stdout``（stdout 重定向已随 Redirector 删除）。"""
    sentinel = object()
    monkeypatch.setattr(sys, "stdout", sentinel)
    monkeypatch.setattr(gui, "build_status_report", _fixed_status_report)
    monkeypatch.setattr(gui, "render_plain", lambda report: "纯文本报告")

    gui_app._run_status()

    assert _pump_until_idle(gui_app), "worker 未在超时内结束"
    assert sys.stdout is sentinel, "快速诊断路径替换了 sys.stdout"
    assert "纯文本报告" in _text(gui_app)


def test_report_rendering_runs_on_main_thread(gui_app, monkeypatch):
    """rich 渲染必须在 Tk 主线程，工作线程只构建 Report。

    回归：rich 首次使用会在工作线程惰性导入 unicode 数据，与 Tk 事件循环并发时
    Windows 直接 fatal exception 0x80000003（栈在 ``render_plain``）。
    """
    called_in: list[threading.Thread] = []

    def recording_render(report: Report) -> str:
        called_in.append(threading.current_thread())
        return "[渲染] 主线程"

    monkeypatch.setattr(gui, "build_status_report", _fixed_status_report)
    monkeypatch.setattr(gui, "render_plain", recording_render)

    gui_app._run_status()

    assert _pump_until_idle(gui_app), "worker 未在超时内结束"
    assert called_in, "render_plain 未被调用"
    assert called_in[0] is threading.main_thread(), "render_plain 必须运行在 Tk 主线程"
    assert "主线程" in _text(gui_app)


def test_quick_diagnose_error_is_shown_in_textbox(gui_app, monkeypatch):
    """报告出错时在文本框显示 ``[错误] ...``，页面不弹窗、busy 正常复位。"""

    def boom() -> Report:
        raise RuntimeError("探测失败")

    monkeypatch.setattr(gui, "build_status_report", boom)
    monkeypatch.setattr(gui, "render_plain", lambda report: "不应走到这里")

    gui_app._run_status()

    assert _pump_until_idle(gui_app), "worker 未在超时内结束"
    assert "[错误] 探测失败" in _text(gui_app)
    assert gui_app.busy is False


def test_quick_diagnose_uses_real_plain_renderer(gui_app, monkeypatch):
    """依赖落地后的集成检查：真实 ``render_plain`` 能渲染出 finding 标题。

    ``netopt.commands.status`` / ``netopt.render.text`` 尚未落地时明确 skip，
    不用假渲染器冒充集成结果。
    """
    if gui.build_status_report is None or gui.render_plain is None:
        pytest.skip("依赖未落地：netopt.commands.status / netopt.render.text（T1.7/T1.4）")
    monkeypatch.setattr(gui, "build_status_report", _fixed_status_report)

    gui_app._run_status()

    assert _pump_until_idle(gui_app), "worker 未在超时内结束"
    assert "快速诊断固定结论" in _text(gui_app)
