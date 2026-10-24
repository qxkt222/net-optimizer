# -*- coding: utf-8 -*-
"""net-optimizer 图形界面 — 主入口（双击 start.bat 启动，或用 pythonw gui.py 运行）。

所有按钮都消费 :class:`netopt.domain.report.Report`（T5.1）：

- **一次性命令按钮**（快速诊断 / 健康评分 / 全面诊断 / 带宽测速 / 延迟测试 /
  DNS 基准 / HTTP 测试 / 路由追踪 / WiFi 检查）在工作线程里**只构建 Report**，
  **主线程**再调 ``render_plain`` 转纯文本插入，**不再**经过 ``sys.stdout``
  重定向与 ANSI 解析（rich 首次使用必须留在主线程）。
- **延迟监控**在 GUI 内直接循环调用 :func:`netopt.probes.ping`，每个 tick 把
  一行纯文本放进队列，结束后显示平均 / 最大 / 丢包汇总。
- **修复按钮**消费 ``netopt.commands.fix`` 的 ``FixPlan`` / ``FixResult``（变更
  日志由 ``apply_fix`` 内部写入），「还原 DNS」走
  :func:`netopt.commands.undo.undo_last`。非管理员仍提权到新控制台窗口执行。

入口薄壳：命令实现全部来自 ``netopt`` 包，重复逻辑一并收敛（D14）——
清除日志走 ``netopt.state.clear``，解释器选择走 ``netopt.platform.console_python``，
提权走 ``netopt.platform``（不再自己碰 ctypes）。
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netopt import VERSION, platform, probes, state
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
from netopt.render.text import render_plain

#: 延迟监控参数（与旧 ``diag.cmd_monitor`` 的默认值一致：60 次 × 1 秒）。
MONITOR_TARGET = "www.baidu.com"
MONITOR_COUNT = 60
MONITOR_INTERVAL = 1.0
MONITOR_TIMEOUT_MS = 1000


# ---------------------------------------------------------------------------
# Report builder（模块级薄包装，便于测试 monkeypatch）
# ---------------------------------------------------------------------------
def build_status_report():
    """「快速诊断」builder 的薄包装。

    每次调用都在**调用时**解析 ``netopt.commands.status.build_status_report``，
    这样测试既可以 patch 本模块属性，也可以 patch 命令层模块属性。
    """
    return cmd_status.build_status_report()


def _build_full_report():
    """「全面诊断」builder —— **惰性导入**。

    ``netopt.commands.full`` 由并行任务落地；模块缺失时只在文本框报错，
    不影响其他按钮（不要把硬 import 放到模块顶层）。
    """
    from netopt.commands.full import build_full_report

    return build_full_report()


# ---------------------------------------------------------------------------
# 纯文本格式化（修复 / 监控）
# ---------------------------------------------------------------------------
def _format_fix_summary(title: str, plan, result) -> str:
    """把修复计划与执行结果压成纯文本：**每个计划步骤一行**。

    ``plan_fix`` 给出步骤描述，``apply_fix`` 的 ``applied`` 按执行顺序记录
    变更 id；这里按顺序把二者对齐，跳过项按 ``target`` 标注。失败原因单独
    成行，最后给一行计数汇总。
    """
    lines = [f"── {title} ──"]
    if plan.blocked_reason is not None and not plan.steps:
        lines.append(f"未执行任何修改：{plan.blocked_reason}")

    remaining_applied = len(result.applied)
    for step in plan.steps:
        if step.target in result.skipped:
            lines.append(f"跳过  {step.description}（已是目标状态）")
        elif remaining_applied > 0:
            lines.append(f"已应用  {step.description}")
            remaining_applied -= 1
        else:
            lines.append(f"未应用  {step.description}")

    for _change_id, error in result.failed:
        lines.append(f"失败  {error}")
    if not plan.steps and plan.blocked_reason is None:
        lines.append("没有需要执行的修复")
    lines.append(
        f"结果：成功 {len(result.applied)} 项，失败 {len(result.failed)} 项，"
        f"跳过 {len(result.skipped)} 项"
    )
    return "\n".join(lines) + "\n"


def _format_undo_summary(result) -> str:
    """把 :class:`netopt.commands.undo.UndoResult` 转成纯文本。"""
    lines = ["── 还原 DNS ──"]
    if result.change_id is not None:
        lines.append(f"变更：{result.change_id}")
    for argv, error in result.failed:
        lines.append(f"失败  {' '.join(argv)}: {error}")
    lines.append(result.message)
    return "\n".join(lines) + "\n"


def _monitor_tick_line(index: int, stat) -> str:
    """监控单个 tick 的一行文本；不可达时明确写“超时/无响应”。"""
    stamp = time.strftime("%H:%M:%S")
    if stat.reachable and stat.avg_ms is not None:
        return f"[{stamp}] #{index}  {stat.avg_ms:.1f} ms"
    return f"[{stamp}] #{index}  超时/无响应"


def _monitor_summary(stats) -> str:
    """汇总监控样本：平均 / 最大 / 丢包率，不拿 0 冒充缺失值。"""
    total = len(stats)
    successful = [stat for stat in stats if stat.reachable and stat.avg_ms is not None]
    loss_pct = 100.0 * (total - len(successful)) / total if total else 0.0
    avg_ms = (
        sum(stat.avg_ms for stat in successful if stat.avg_ms is not None) / len(successful)
        if successful
        else None
    )
    max_ms = max(
        (stat.max_ms for stat in successful if stat.max_ms is not None),
        default=None,
    )
    avg_text = f"{avg_ms:.1f}" if avg_ms is not None else "-"
    max_text = f"{max_ms:.1f}" if max_ms is not None else "-"
    return (
        "── 延迟监控汇总 ──\n"
        f"样本 {total} 次，成功 {len(successful)} 次，丢包率 {loss_pct:.1f}%\n"
        f"平均 {avg_text} ms，最大 {max_text} ms\n"
    )


def _monitor_loop(
    put,
    stop_event,
    *,
    target: str = MONITOR_TARGET,
    count: int = MONITOR_COUNT,
    interval: float = MONITOR_INTERVAL,
    ping=None,
) -> list:
    """在**工作线程**里跑延迟监控；每个 tick 通过 ``put`` 交出一行纯文本。

    - ``ping`` 默认在**调用时**解析为 :func:`netopt.probes.ping`，便于测试注入；
    - 每个 tick 固定发 1 个包（``count=1``、``timeout_ms=1000``）；
    - 停止用 ``stop_event.wait(interval)`` 实现，收到停止请求后最多再等一个
      间隔就退出；测试传 ``interval=0`` 即可完全不等待；
    - 无论是否被提前停止，最后都会交出汇总行。
    """
    probe = ping if ping is not None else probes.ping
    stats = []
    for index in range(1, count + 1):
        if stop_event.is_set():
            break
        stat = probe(target, 1, timeout_ms=MONITOR_TIMEOUT_MS)
        stats.append(stat)
        put(_monitor_tick_line(index, stat))
        if stop_event.wait(interval):
            break
    put(_monitor_summary(stats))
    return stats


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"net-optimizer v{VERSION} — Windows 网络优化工具")
        self.geometry("780x680")
        self.minsize(640, 480)
        self.q = queue.Queue()
        self.busy = False
        self.stop_event = threading.Event()
        self._build_ui()
        self.after(80, self._poll)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        top = ttk.Frame(self, padding=(8, 6))
        top.pack(fill="x")
        ttk.Label(
            top, text=f"net-optimizer  v{VERSION}", font=("Microsoft YaHei UI", 12, "bold")
        ).pack(side="left")
        self.status_lbl = ttk.Label(
            top,
            font=("Microsoft YaHei UI", 9),
            text="状态: 管理员" if platform.is_admin() else "状态: 普通用户 (修复功能将自动提权)",
        )
        self.status_lbl.pack(side="right")

        btns = ttk.Frame(self, padding=(8, 0))
        btns.pack(fill="x")
        for row in [
            [
                ("快速诊断", self._run_status),
                # builder 在按钮回调里按名字解析，测试可直接 patch 命令层模块属性。
                ("健康评分", lambda: self._run_report(cmd_health.build_health_report)),
                ("全面诊断", lambda: self._run_report(_build_full_report)),
                ("带宽测速", lambda: self._run_report(cmd_speed.build_speed_report)),
            ],
            [
                ("延迟测试", lambda: self._run_report(cmd_ping.build_ping_report)),
                ("DNS 基准", lambda: self._run_report(cmd_dns.build_dns_report)),
                ("HTTP 测试", lambda: self._run_report(cmd_http.build_http_report)),
                ("路由追踪", lambda: self._run_report(cmd_trace.build_trace_report)),
            ],
            [
                ("WiFi 检查", lambda: self._run_report(cmd_wifi.build_wifi_report)),
                ("延迟监控", self._run_monitor),
                ("清除日志", self._clear),
                ("打开说明", self._readme),
            ],
        ]:
            f = ttk.Frame(btns)
            f.pack(fill="x", pady=(0, 6))
            for text, fn in row:
                ttk.Button(f, text=text, width=12, command=fn).pack(side="left", padx=(0, 6))

        admin = ttk.Frame(self, padding=(8, 4))
        admin.pack(fill="x")
        ttk.Label(admin, text="修复 (需管理员):", font=("Microsoft YaHei UI", 9)).pack(side="left")
        for text, fn in [
            ("一键优化 auto", self._run_fix_auto),
            ("修复 DNS", lambda: self._run_fix("dns")),
            ("修复 TCP", lambda: self._run_fix("tcp")),
            ("修复电源", lambda: self._run_fix("power")),
            ("还原 DNS", lambda: self._run_fix("dns", restore=True)),
        ]:
            ttk.Button(admin, text=text, command=fn).pack(side="left", padx=(0, 6))
        self.relaunch_btn = ttk.Button(admin, text="以管理员重启", command=self._relaunch_admin)
        self.relaunch_btn.pack(side="right")
        self.stop_btn = ttk.Button(admin, text="停止 (监控)", command=self._stop, state="disabled")
        self.stop_btn.pack(side="right")

        self.text = scrolledtext.ScrolledText(
            self, wrap="char", font=("Consolas", 9), bg="#0d1117", fg="#e6edf3"
        )
        self.text.pack(fill="both", expand=True, padx=8, pady=(8, 8))
        self._out("net-optimizer 就绪。卡顿时点“快速诊断”定位问题，或直接点“一键优化”。\n\n")
        if platform.is_admin():
            self._out("[提示] 已以管理员运行 — 修复功能直接在本窗口执行。\n")
        else:
            self._out("[提示] 当前未以管理员运行，修复功能会弹出 UAC 到新窗口执行；\n")
            self._out("       也可点右上角“以管理员重启”让本窗口变成管理员模式。\n")

    # -------------------------------------------------------------- 任务调度
    def _start_task(self, worker, *args) -> bool:
        """启动一个后台任务；已有任务时提示并拒绝（busy 互斥）。"""
        if self.busy:
            self._out("[提示] 有任务正在运行，请等待完成。\n")
            return False
        self.busy = True
        self.stop_event.clear()
        self.stop_btn.config(state="normal")
        threading.Thread(target=worker, args=args, daemon=True).start()
        return True

    def _run_report(self, builder):
        """一次性命令按钮：工作线程只构建 Report，渲染留给主线程 ``_poll``。"""
        self._start_task(self._report_worker, builder)

    def _run_status(self):
        """「快速诊断」：直接消费 ``Report``，不经 stdout 重定向与 ANSI 解析（T1.8）。"""
        self._run_report(build_status_report)

    def _report_worker(self, builder):
        """工作线程：**只构建 Report**，随队列交给主线程渲染。

        与 :meth:`_fix_worker` / :meth:`_monitor_worker` 一样**不替换**
        ``sys.stdout`` / ``sys.stderr``。

        这里绝不能调用 ``render_plain``：rich 首次使用会惰性导入 unicode 数据
        （可能触发字节码编译 / GC），若发生在工作线程，会与 Tk 主线程事件循环
        并发，在 Windows 上直接致命异常（0x80000003）。渲染见 :meth:`_render_report`。
        """
        try:
            self.q.put(("__report__", builder()))
        except Exception as e:  # 报告出错只在文本框提示，不弹窗
            self._put_error(e)
        finally:
            self.q.put(("__done__", None))

    def _render_report(self, report):
        """在 **Tk 主线程** 渲染 Report 并插入文本框（T1.8）。

        rich 的惰性 unicode 数据必须在主线程首次加载，原因见
        :meth:`_report_worker`。渲染失败同样只在文本框提示，不弹窗。
        """
        try:
            text = render_plain(report)
        except Exception as e:
            self._insert_plain(f"\n[错误] {e}\n")
            if state.DEV_ON:
                import traceback

                self._insert_plain(traceback.format_exc())
            return
        self._insert_plain(text if text.endswith("\n") else text + "\n")

    def _put_error(self, exc: Exception) -> None:
        """把异常写进队列；dev 模式额外附上 traceback。"""
        self.q.put(("__plain__", f"\n[错误] {exc}\n"))
        if state.DEV_ON:
            import traceback

            self.q.put(("__plain__", traceback.format_exc()))

    # -------------------------------------------------------------- 延迟监控
    def _run_monitor(self):
        """「延迟监控」：GUI 内循环 ping，不再走 ``diag.cmd_monitor``。"""
        self._start_task(self._monitor_worker)

    def _monitor_worker(self):
        try:
            _monitor_loop(
                lambda line: self.q.put(("__plain__", line + "\n")),
                self.stop_event,
            )
        except Exception as e:
            self._put_error(e)
        finally:
            self.q.put(("__done__", None))

    # ------------------------------------------------------------------ 修复
    def _run_fix(self, what, restore=False):
        """修复按钮：管理员时直接在本窗口执行，否则提权到新控制台窗口。

        ``restore=True`` 是「还原 DNS」按钮：对应 ``undo_last(kind="dns")``。
        """
        if self.busy:
            self._out("[提示] 有任务正在运行，请等待完成。\n")
            return
        if not platform.is_admin():
            self._run_admin(f"fix {what}" + (" --restore" if restore else ""))
            return
        if restore:
            self._start_task(self._undo_worker)
        else:
            self._start_task(self._fix_worker, cmd_fix.FixKind(what), f"修复 {what}")

    def _run_fix_auto(self):
        """「一键优化」= ``apply_fix(FixKind.all)``（v1 的复测对比不迁移）。"""
        if self.busy:
            self._out("[提示] 有任务正在运行，请等待完成。\n")
            return
        if not platform.is_admin():
            self._run_admin("auto")
            return
        self._start_task(self._fix_worker, cmd_fix.FixKind.all, "一键优化")

    def _fix_worker(self, kind, title):
        """工作线程：先 ``plan_fix`` 拿步骤，再 ``apply_fix`` 执行。

        变更日志（intent → complete/fail）由 ``apply_fix`` 内部写入
        :class:`netopt.system.journal.Journal`，GUI 不直接读写 journal。
        """
        try:
            plan = cmd_fix.plan_fix(kind)
            result = cmd_fix.apply_fix(kind)
            self.q.put(("__plain__", _format_fix_summary(title, plan, result)))
        except Exception as e:
            self._put_error(e)
        finally:
            self.q.put(("__done__", None))

    def _undo_worker(self):
        """工作线程：「还原 DNS」——回滚最后一条 DNS 变更。"""
        try:
            result = cmd_undo.undo_last(kind="dns")
            self.q.put(("__plain__", _format_undo_summary(result)))
        except Exception as e:
            self._put_error(e)
        finally:
            self.q.put(("__done__", None))

    # ------------------------------------------------------------------ 输出
    def _poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item == ("__done__", None):
                    self.busy = False
                    self.stop_btn.config(state="disabled")
                    self._out("\n────── 完成 ──────\n")
                elif isinstance(item, tuple) and item and item[0] == "__report__":
                    # 渲染必须在主线程（rich 惰性加载 unicode 数据，见 _report_worker）
                    self._render_report(item[1])
                elif isinstance(item, tuple) and item and item[0] == "__plain__":
                    # 纯文本原样插入（不解析 ANSI）
                    self._insert_plain(item[1])
                else:
                    self._out(item)
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _insert_plain(self, s):
        """插入纯文本，不做 ANSI / ``\\r`` 处理（T5.1：统一入口）。"""
        self.text.config(state="normal")
        self.text.insert("end", s)
        self.text.see("end")
        self.text.config(state="disabled")

    def _out(self, s):
        """插入纯文本；以 ``\\r`` 开头表示覆盖当前行（监控 tick 用，D7）。

        旧实现还会解析 ANSI 颜色码，T5.1 起已彻底删除（GUI 只消费纯文本）。
        """
        if s.startswith("\r"):
            # D7 修复：旧实现 delete("insert-1c lineend", "end-1c") 的删除区间
            # 退化为空（插入点总在文末时两界重合），每次 tick 变成追加。
            # 这里显式删「最后一行的行首 → 文末」，即真正覆盖当前行。
            self.text.config(state="normal")
            self.text.delete(self.text.index("end-1c linestart"), "end-1c")
            self.text.config(state="disabled")
            s = s.lstrip("\r")
        self._insert_plain(s)

    def _stop(self):
        self.stop_event.set()
        self._out("[提示] 已请求停止（延迟监控会立即停下）。\n")

    def _clear(self):
        """清除日志/历史/dev 标志；统一走 ``state.clear``（D14，保留 DNS 备份）。"""
        removed = state.clear()
        self._out(("已清除: " + ", ".join(removed) + "\n") if removed else "没有需要清除的文件\n")

    def _readme(self):
        try:
            os.startfile(str(state.BASE / "README.md"))
        except Exception:
            self._out("未找到 README.md\n")

    def _relaunch_admin(self):
        """以管理员身份重启本 GUI（新窗口），旧窗口可关闭。"""
        if platform.is_admin():
            self._out("[提示] 当前已是管理员。\n")
            return
        if platform.elevate([]):
            self._out("[提示] 已以管理员身份启动新窗口，本窗口可以关闭。\n")
        else:
            self._out("[提示] 提权被取消。\n")

    def _run_admin(self, cmd):
        """管理员类命令：提权到新控制台窗口执行，--wait 让窗口停留等回车。

        解释器用 ``platform.console_python()``（D14：pythonw 提权后新窗口没有任何
        输出）；ShellExecute 走 ``platform._shell_execute`` —— 那是 platform 模块
        唯一的提权注入点，集中在此避免 GUI 自己碰 ctypes。
        """
        if self.busy:
            self._out("[提示] 有任务正在运行，请等待完成。\n")
            return
        script = state.BASE / "netoptimizer.py"
        params = f'"{script}" {cmd} --wait'
        r = platform._shell_execute("runas", platform.console_python(), params, str(state.BASE))
        if r > 32:
            self._out(f"[提示] 已以管理员身份启动 “{cmd}”，结果在新窗口显示，完成后按回车关闭。\n")
        else:
            self._out("[提示] 提权被取消。\n")


if __name__ == "__main__":
    app = App()
    if "--smoke" in sys.argv:  # 冒烟测试：启动 1.5 秒后自动退出
        app.after(1500, app.destroy)
    app.mainloop()
