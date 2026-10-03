# -*- coding: utf-8 -*-
"""net-optimizer 图形界面 — 主入口（双击 start.bat 启动，或用 pythonw gui.py 运行）。

所有按钮命令在工作线程中执行，print 输出被重定向到界面文本框，
颜色通过解析 ANSI 码映射为文本标签。任一时刻只允许一个任务运行。

入口薄壳：命令实现全部来自 ``netopt`` 包，重复逻辑一并收敛（D14）——
清除日志走 ``netopt.state.clear``，解释器选择走 ``netopt.platform.console_python``，
提权走 ``netopt.platform``（不再自己碰 ctypes）。
"""

import os
import queue
import re
import sys
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netopt import VERSION, diag, fix, health, platform, state

ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")
#: ANSI 码 → tk 文本标签。``1``（粗体）由 netopt.ui.bold 使用；旧实现漏了它，
#: 导致 ``\033[1m`` 之后的文本继承上一个颜色而不是回到默认色。
COLOR_TAGS = {"92": "green", "93": "yellow", "91": "red", "96": "cyan", "1": "bold"}


class Redirector:
    """把 worker 线程的 print 输出重定向进队列。"""

    def __init__(self, q):
        self.q = q

    def write(self, s):
        self.q.put(s)

    def flush(self):
        pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"net-optimizer v{VERSION} — Windows 网络优化工具")
        self.geometry("780x680")
        self.minsize(640, 480)
        self.q = queue.Queue()
        self.busy = False
        self.stop_event = threading.Event()
        self._cur_tag = None
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
                ("快速诊断", lambda: self._run(diag.cmd_status)),
                ("健康评分", lambda: self._run(health.cmd_health)),
                ("全面诊断", lambda: self._run(diag.cmd_full)),
                ("带宽测速", lambda: self._run(diag.cmd_speed)),
            ],
            [
                ("延迟测试", lambda: self._run(diag.cmd_ping)),
                ("DNS 基准", lambda: self._run(diag.cmd_dns)),
                ("HTTP 测试", lambda: self._run(diag.cmd_http)),
                ("路由追踪", lambda: self._run(diag.cmd_trace)),
            ],
            [
                ("WiFi 检查", lambda: self._run(diag.cmd_wifi)),
                ("延迟监控", lambda: self._run(diag.cmd_monitor, 60, self.stop_event)),
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
        self.text.tag_configure("green", foreground="#2ecc71")
        self.text.tag_configure("yellow", foreground="#f1c40f")
        self.text.tag_configure("red", foreground="#e74c3c")
        self.text.tag_configure("cyan", foreground="#00bcd4")
        self.text.tag_configure("bold", foreground="#e6edf3", font=("Consolas", 9, "bold"))
        self._out("net-optimizer 就绪。卡顿时点“快速诊断”定位问题，或直接点“一键优化”。\n\n")
        if platform.is_admin():
            self._out("[提示] 已以管理员运行 — 修复功能直接在本窗口执行。\n")
        else:
            self._out("[提示] 当前未以管理员运行，修复功能会弹出 UAC 到新窗口执行；\n")
            self._out("       也可点右上角“以管理员重启”让本窗口变成管理员模式。\n")

    # -------------------------------------------------------------- 执行
    def _run(self, fn, *args):
        if self.busy:
            self._out("[提示] 有任务正在运行，请等待完成。\n")
            return
        self.busy = True
        self.stop_event.clear()
        self.stop_btn.config(state="normal")
        threading.Thread(target=self._worker, args=(fn, *args), daemon=True).start()

    def _worker(self, fn, *args):
        old_out, old_err = sys.stdout, sys.stderr
        try:
            sys.stdout = sys.stderr = Redirector(self.q)
            fn(*args)
        except Exception as e:
            print(f"\n[错误] {e}")
            if state.DEV_ON:
                import traceback

                traceback.print_exc()
        finally:
            sys.stdout, sys.stderr = old_out, old_err
            self.q.put(("__done__", None))

    def _poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item == ("__done__", None):
                    self.busy = False
                    self.stop_btn.config(state="disabled")
                    self._out("\n────── 完成 ──────\n")
                else:
                    self._out(item)
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _out(self, s):
        self.text.config(state="normal")
        if s.startswith("\r"):  # monitor 用 \r 刷新同一行 → 删除当前行已有内容
            # D7 修复：旧实现 delete("insert-1c lineend", "end-1c") 的删除区间
            # 退化为空（插入点总在文末时两界重合），每次 tick 变成追加。
            # 这里显式删「最后一行的行首 → 文末」，即真正覆盖当前行。
            self.text.delete(self.text.index("end-1c linestart"), "end-1c")
            s = s.lstrip("\r")
        pos = 0
        for m in ANSI_RE.finditer(s):
            if m.start() > pos:
                self._insert(s[pos : m.start()])
            code = m.group(1)
            if code in ("0", ""):
                self._cur_tag = None
            elif code in COLOR_TAGS:
                self._cur_tag = COLOR_TAGS[code]
            pos = m.end()
        if pos < len(s):
            self._insert(s[pos:])
        self.text.see("end")
        self.text.config(state="disabled")

    def _insert(self, s):
        if self._cur_tag:
            self.text.insert("end", s, self._cur_tag)
        else:
            self.text.insert("end", s)

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

    def _run_fix(self, what, restore=False):
        """修复按钮：管理员时直接在本窗口执行，否则提权到新控制台窗口。

        ``restore=True`` 是「还原 DNS」按钮：对应 CLI ``fix dns --restore``。
        """
        if self.busy:
            self._out("[提示] 有任务正在运行，请等待完成。\n")
            return
        if platform.is_admin():
            self._out(f"── {'还原' if restore else '修复'} {what} ──\n")
            self._run(lambda: fix.cmd_fix(what, restore=restore))
        else:
            self._run_admin(f"fix {what}" + (" --restore" if restore else ""))

    def _run_fix_auto(self):
        if self.busy:
            self._out("[提示] 有任务正在运行，请等待完成。\n")
            return
        if platform.is_admin():
            self._run(fix.cmd_auto)
        else:
            self._run_admin("auto")

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
