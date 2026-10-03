"""系统边界层 —— 本项目**唯一**允许执行系统命令 / 触碰 ctypes 的模块。

约定（见 BRIEF §2/§5）：

- :func:`run` 返回 :class:`CmdResult`，用 ``timed_out`` / ``missing`` 区分失败原因。
  旧实现两者都返回 ``-1``，调用方只能猜，把超时显示成「系统不支持」（缺陷 D9）。
- 原始输出回显（旧 ``netlib.run(show=)`` / ``DEV_ON``）**不在本模块**：这里只保证
  ``CmdResult.out`` 携带完整文本，由编排层决定怎么显示。
- 提权用 :func:`console_python` 选解释器，避免从 ``pythonw.exe``（GUI）提权后
  新窗口没有任何输出（缺陷 D14）。
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class CmdResult:
    """一条系统命令的执行结果（字段为冻结契约）。

    ``ok`` 同时要求「退出码 0」且「不是超时/命令不存在」——旧代码用 ``code == 0``
    判断时，超时返回的 ``-1`` 恰好不为 0 所以没出事，但 ``code`` 本身无法区分失败
    原因，故新增两个布尔字段。
    """

    argv: list[str]
    code: int
    out: str
    timed_out: bool = False
    missing: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0 and not self.timed_out and not self.missing


#: 可注入的命令执行器签名：``(argv, timeout=30.0) -> CmdResult``。
Runner = Callable[..., CmdResult]

# Windows 下隐藏子进程控制台窗口；非 Windows 上该常量不存在，取 0。
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def decode_out(data: bytes) -> str:
    """把命令原始字节解码为文本：优先 UTF-8，回退 GBK（中文 Windows 输出）。"""
    if not data:
        return ""
    for enc in ("utf-8", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def run(argv: list[str], timeout: float = 30.0) -> CmdResult:
    """执行一条系统命令。**永不抛异常**，失败原因写进 :class:`CmdResult`。

    - 超时 → ``timed_out=True``，``out`` 是可读说明；
    - 命令不存在 → ``missing=True``；
    - 其它 OSError（权限等）→ ``code=-1`` 且 ``out`` 带系统错误文本。
    """
    argv = [str(a) for a in argv]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        return CmdResult(
            argv=argv,
            code=-1,
            out=f"命令执行超时（超过 {timeout:g} 秒）：{' '.join(argv)}",
            timed_out=True,
        )
    except FileNotFoundError:
        return CmdResult(
            argv=argv,
            code=-1,
            out=f"找不到命令：{argv[0]}",
            missing=True,
        )
    except OSError as exc:
        return CmdResult(argv=argv, code=-1, out=str(exc))
    return CmdResult(
        argv=argv,
        code=proc.returncode,
        out=decode_out(proc.stdout) + decode_out(proc.stderr),
    )


def is_admin() -> bool:
    """当前进程是否以管理员身份运行；非 Windows 或无权限接口时返回 False。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def console_python() -> str:
    """返回**带控制台**的 Python 解释器路径。

    GUI 从 ``pythonw.exe`` 启动时 ``sys.executable`` 是 pythonw.exe，用它提权
    （ShellExecute runas）弹出的新窗口不会显示任何输出。这里换成同目录的
    ``python.exe``（缺陷 D14）。
    """
    exe = sys.executable or "python"
    if os.path.basename(exe).lower() == "pythonw.exe":
        console = os.path.join(os.path.dirname(exe), "python.exe")
        if os.path.exists(console):
            return console
    return exe


def _shell_execute(operation: str, file: str, params: str, cwd: str) -> int:
    """``ShellExecuteW`` 的最小包装。

    单独成函数是为了给测试一个注入点：测试里替换它即可验证提权参数，
    **不会真的弹 UAC / 启动进程**。
    """
    return ctypes.windll.shell32.ShellExecuteW(None, operation, file, params, cwd, 1)


def elevate(args: list[str], *, exe: str | None = None) -> bool:
    """以管理员身份重新启动本程序，返回是否成功发起提权（UAC 被取消则为 False）。

    ``args`` 是传给本脚本的命令行参数；``exe`` 覆盖解释器，默认
    :func:`console_python`（而不是可能无控制台的 ``sys.executable``）。
    """
    script = os.path.abspath(sys.argv[0])
    quoted = [f'"{a}"' if " " in str(a) else str(a) for a in args]
    params = f'"{script}" {" ".join(quoted)}'.strip()
    try:
        r = _shell_execute("runas", exe or console_python(), params, os.path.dirname(script))
        return r > 32
    except Exception:
        return False


def init_console() -> None:
    """开启 ANSI 转义并强制 UTF-8（合并旧 ``_init_color`` / ``_init_utf8``）。

    非 Windows、pythonw（无控制台）、被重定向的流……任何一步失败都必须静默跳过，
    绝不能在 import 时炸掉。
    """
    kernel32 = None
    with contextlib.suppress(Exception):
        kernel32 = ctypes.windll.kernel32

    if kernel32 is not None:
        with contextlib.suppress(Exception):
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL
        with contextlib.suppress(Exception):
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)

    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(encoding="utf-8", errors="replace")


# 旧 netlib.py 在 import 时就初始化控制台，保持同样的行为。
init_console()
