# -*- coding: utf-8 -*-
"""net-optimizer — Windows 网络诊断与一键优化工具
用法: python netoptimizer.py <命令> [参数]

入口薄壳（BRIEF §5）：只做参数解析、管理员提权与命令分发，
诊断/修复/评分逻辑全部在 :mod:`netopt` 包里。

命名冲突提醒：项目根目录还有**旧的** ``diag.py`` / ``fix.py`` / ``health.py``，
本模块一律用显式包路径 ``from netopt import ...``，绝不裸 ``import diag``。

``fix`` 额外支持 ``--restore``：``python netoptimizer.py fix dns --restore``
→ ``netopt.fix.cmd_fix("dns", restore=True)``（把 DNS 还原成 ``fix dns`` 修改前的原值）。
"""

import contextlib
import sys

from netopt import VERSION, diag, fix, health, platform, state, ui

# 需要管理员权限的命令
NEED_ADMIN = {"fix", "auto", "dev"}

HELP = f"""net-optimizer v{VERSION} — Windows 网络诊断与一键优化工具

用法: python netoptimizer.py <命令> [参数]

  命令                    功能
  ─────────────────────────────────────────────────────────
  status                  快速诊断 (Ping+DNS+HTTP+MTU)
  full                    全面诊断 (含带宽/路由/WiFi)
  auto                    一键优化 (诊断→自动修复全部, 需管理员)
  ping [目标]             延迟测试 (默认百度)
  dns                     DNS 解析基准 (7 个服务器)
  http                    HTTP 延迟测试 (4 个站点)
  speed                   带宽测速 (下载+上传)
  trace [目标]            路由追踪 (默认百度)
  wifi                    WiFi 信号/信道/频段
  fix dns/tcp/power       自动修复 (需管理员; dns 只改默认路由网卡, 改前先备份)
  fix dns --restore       把 DNS 还原成修改前的原值 (需管理员)
  monitor [次数]          百度延迟采样 (默认 60 次)
  dev on/off              开发者模式 (需管理员, 回显原始命令)
  health                  健康评分+优化建议
  admin                   以管理员身份重启本程序
  clear                   清除日志/历史/dev 标志 (保留 dns-backup.json)
  help                    显示本帮助
"""


def cmd_help() -> None:
    print(HELP)


def cmd_clear() -> None:
    """清除日志/历史/dev 标志（统一走 ``netopt.state.clear``，D14）。

    保留 ``dns-backup.json``——那是 ``fix dns`` 备份、``fix dns --restore`` 还原用的。
    """
    removed = state.clear()
    if removed:
        print(ui.green(f"已清除: {', '.join(removed)}"))
    else:
        print("没有需要清除的文件")
    state.log("clear 完成")


def cmd_dev(mode: str) -> None:
    """开关开发者模式：写/删 ``state.DEV_FILE``，并同步本进程的 ``state.DEV_ON``。

    原始输出回显由 ``netopt.diag`` 编排层读 ``state.DEV_ON`` 实现，这里只负责开关。
    """
    if mode == "on":
        with open(state.DEV_FILE, "w", encoding="utf-8") as f:
            f.write('{"dev": true}')
        state.DEV_ON = True
        print(ui.green("开发者模式已开启 — 将回显所有系统命令的原始输出"))
    else:
        with contextlib.suppress(OSError):
            state.DEV_FILE.unlink()
        state.DEV_ON = False
        print(ui.green("开发者模式已关闭"))
    state.log(f"dev {mode}")


def cmd_admin() -> None:
    print(ui.yellow("正在以管理员身份重新启动..."))
    if not platform.elevate(sys.argv[1:]):
        print(ui.red("提权被取消或失败"))


def main(argv: list[str]) -> int:
    state.load_dev()
    argv = [a for a in argv if a != "--wait"]  # --wait 由 __main__ 处理
    if not argv:
        cmd_help()
        return 0

    cmd = argv[0].lower()
    args = argv[1:]

    # 需要管理员权限的命令: 非管理员时自动提权重启
    if cmd in NEED_ADMIN and not platform.is_admin():
        print(ui.yellow(f"[提示] '{cmd}' 需要管理员权限, 正在以管理员身份重新启动..."))
        print(ui.yellow('       如果弹出 UAC 窗口请点击"是", 结果在新窗口显示'))
        if not platform.elevate([*argv, "--wait"]):
            print(ui.red("提权被取消"))
        return 0

    state.log(f"运行: {' '.join(argv)}")

    try:
        if cmd == "status":
            diag.cmd_status()
        elif cmd == "full":
            diag.cmd_full()
        elif cmd == "auto":
            fix.cmd_auto()
        elif cmd == "ping":
            diag.cmd_ping(args[0] if args else None)
        elif cmd == "dns":
            diag.cmd_dns()
        elif cmd == "http":
            diag.cmd_http()
        elif cmd == "speed":
            diag.cmd_speed()
        elif cmd == "trace":
            diag.cmd_trace(args[0] if args else None)
        elif cmd == "wifi":
            diag.cmd_wifi()
        elif cmd == "fix":
            # fix [dns|tcp|power|all] [--restore]；--restore 只对 dns 有效
            restore = "--restore" in args
            rest = [a for a in args if a != "--restore"]
            fix.cmd_fix(rest[0] if rest else "all", restore=restore)
        elif cmd == "monitor":
            count = 60
            if args and args[0].isdigit():
                count = min(max(int(args[0]), 5), 600)
            diag.cmd_monitor(count)
        elif cmd == "dev":
            if args and args[0].lower() in ("on", "off"):
                cmd_dev(args[0].lower())
            else:
                print("用法: dev on|off")
        elif cmd == "health":
            health.cmd_health()
        elif cmd == "admin":
            cmd_admin()
        elif cmd == "clear":
            cmd_clear()
        elif cmd in ("help", "-h", "--help"):
            cmd_help()
        else:
            print(ui.red(f"未知命令: {cmd}"))
            print(HELP)
    except KeyboardInterrupt:
        print("\n已中断")
    except Exception as e:
        print(ui.red(f"出错: {e}"))
        state.log(f"错误: {e}")
        if state.DEV_ON:
            import traceback

            traceback.print_exc()
    return 0


if __name__ == "__main__":
    wait = "--wait" in sys.argv
    code = main(sys.argv[1:])
    if wait:
        input("\n按回车键退出...")
    sys.exit(code)
