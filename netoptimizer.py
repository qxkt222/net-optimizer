# -*- coding: utf-8 -*-
"""net-optimizer — Windows 网络诊断与一键优化工具
用法: python netoptimizer.py <命令> [参数]
"""
import glob
import os
import sys

import diag
import fix
import health
import netlib as nl

VERSION = "1.0"

# 需要管理员权限的命令
NEED_ADMIN = {"fix", "auto", "dev"}

HELP = """net-optimizer v%s — Windows 网络诊断与一键优化工具

用法: python netoptimizer.py <命令> [参数]

  命令                功能
  ─────────────────────────────────────────────────────
  status              快速诊断 (Ping+DNS+HTTP+MTU)
  full                全面诊断 (含带宽/路由/WiFi)
  auto                一键优化 (诊断→自动修复全部, 需管理员)
  ping [目标]         延迟测试 (默认百度)
  dns                 DNS 解析基准 (7 个服务器)
  http                HTTP 延迟测试 (4 个站点)
  speed               带宽测速 (下载+上传)
  trace [目标]        路由追踪 (默认百度)
  wifi                WiFi 信号/信道/频段
  fix dns/tcp/power   自动修复 (需管理员)
  monitor [次数]      百度延迟采样 (默认 60 次)
  dev on/off          开发者模式 (需管理员, 回显原始命令)
  health              健康评分+优化建议
  admin               以管理员身份重启本程序
  clear               清除日志和诊断历史
  help                显示本帮助
""" % VERSION

def cmd_help():
    print(HELP)

def cmd_clear():
    removed = []
    for f in glob.glob(os.path.join(nl.BASE, "log-*.log")) + [nl.HISTORY_FILE, nl.DEV_FILE]:
        if os.path.exists(f):
            try:
                os.remove(f)
                removed.append(os.path.basename(f))
            except OSError:
                pass
    if removed:
        print(nl.green(f"已清除: {', '.join(removed)}"))
    else:
        print("没有需要清除的文件")
    nl.log("clear 完成")

def cmd_dev(mode):
    if mode == "on":
        with open(nl.DEV_FILE, "w", encoding="utf-8") as f:
            f.write('{"dev": true}')
        print(nl.green("开发者模式已开启 — 将回显所有系统命令的原始输出"))
    else:
        if os.path.exists(nl.DEV_FILE):
            os.remove(nl.DEV_FILE)
        print(nl.green("开发者模式已关闭"))
    nl.log(f"dev {mode}")

def cmd_admin():
    print(nl.yellow("正在以管理员身份重新启动..."))
    ok = nl.elevate(*sys.argv[1:])
    if not ok:
        print(nl.red("提权被取消或失败"))

def main(argv):
    nl.load_dev()
    argv = [a for a in argv if a != "--wait"]  # --wait 由 __main__ 处理
    if not argv:
        cmd_help()
        return 0

    cmd = argv[0].lower()
    args = argv[1:]

    # 需要管理员权限的命令: 非管理员时自动提权重启
    if cmd in NEED_ADMIN and not nl.is_admin():
        print(nl.yellow(f"[提示] '{cmd}' 需要管理员权限, 正在以管理员身份重新启动..."))
        print(nl.yellow("       如果弹出 UAC 窗口请点击\"是\", 结果在新窗口显示"))
        ok = nl.elevate(*argv, "--wait")
        if not ok:
            print(nl.red("提权被取消"))
        return 0

    nl.log(f"运行: {' '.join(argv)}")

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
            fix.cmd_fix(args[0] if args else "all")
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
            print(nl.red(f"未知命令: {cmd}"))
            print(HELP)
    except KeyboardInterrupt:
        print("\n已中断")
    except Exception as e:
        print(nl.red(f"出错: {e}"))
        nl.log(f"错误: {e}")
        if nl.DEV_ON:
            import traceback
            traceback.print_exc()
    return 0

if __name__ == "__main__":
    wait = "--wait" in sys.argv
    code = main(sys.argv[1:])
    if wait:
        input("\n按回车键退出...")
    sys.exit(code)
