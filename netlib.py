# -*- coding: utf-8 -*-
"""net-optimizer 公共工具库：系统命令、提权、日志、历史、探测原语。"""
import ctypes
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE, "history.json")
DEV_FILE = os.path.join(BASE, "dev.json")

DEV_ON = False  # 开发者模式：回显所有系统命令原始输出

# ---------------------------------------------------------------------------
# 彩色输出
# ---------------------------------------------------------------------------
def _init_color():
    try:
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)  # 启用 ANSI 转义
    except Exception:
        pass

def _init_utf8():
    """强制 stdout/stderr 使用 UTF-8, 并同步切换控制台代码页, 避免中文乱码。"""
    try:
        k = ctypes.windll.kernel32
        k.SetConsoleOutputCP(65001)
        k.SetConsoleCP(65001)
    except Exception:
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

_init_color()
_init_utf8()
N = "\033[0m"
def green(t):  return f"\033[92m{t}{N}"
def yellow(t): return f"\033[93m{t}{N}"
def red(t):    return f"\033[91m{t}{N}"
def cyan(t):   return f"\033[96m{t}{N}"
def bold(t):   return f"\033[1m{t}{N}"

# ---------------------------------------------------------------------------
# 管理员检测 / 提权
# ---------------------------------------------------------------------------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def elevate(*args):
    """以管理员身份重新启动自身（ShellExecute runas），返回是否成功弹出 UAC。"""
    script = os.path.abspath(sys.argv[0])
    quoted = [f'"{a}"' if " " in str(a) else str(a) for a in args]
    params = f'"{script}" {" ".join(quoted)}'.strip()
    try:
        r = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, os.path.dirname(script), 1)
        return r > 32
    except Exception:
        return False

# ---------------------------------------------------------------------------
# 系统命令封装
# ---------------------------------------------------------------------------
def decode_out(b: bytes) -> str:
    for enc in ("utf-8", "gbk"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return b.decode("utf-8", errors="replace")

def run(cmd, timeout=30, show=False):
    """执行系统命令，返回 (返回码, 输出文本)。dev 模式或 show=True 时回显原始输出。"""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        text = decode_out(p.stdout) + decode_out(p.stderr)
        if DEV_ON or show:
            print(text.rstrip())
        return p.returncode, text
    except subprocess.TimeoutExpired:
        return -1, ""
    except FileNotFoundError:
        return -1, ""

# ---------------------------------------------------------------------------
# 日志 / 历史
# ---------------------------------------------------------------------------
def log(msg):
    """追加一行到当天的日志文件（项目根目录 log-YYYY-MM-DD.log）。"""
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        fn = os.path.join(BASE, "log-" + time.strftime("%Y-%m-%d") + ".log")
        with open(fn, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass

def hist_load():
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"entries": []}

def hist_add(entry):
    """entry: {"cmd": ..., "ts": ..., "score": ..., "detail": {...}}"""
    try:
        h = hist_load()
        h.setdefault("entries", []).append(entry)
        h["entries"] = h["entries"][-200:]
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(h, f, ensure_ascii=False, indent=1)
    except Exception:
        pass

def load_dev():
    global DEV_ON
    try:
        with open(DEV_FILE, encoding="utf-8") as f:
            DEV_ON = bool(json.load(f).get("dev"))
    except Exception:
        DEV_ON = False

# ---------------------------------------------------------------------------
# 探测原语
# ---------------------------------------------------------------------------
def ping_stats(target, count=4, timeout_ms=1000):
    """ping 统计，返回 {min, avg, max, jitter, loss_pct, replies}。"""
    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), target]
    total_timeout = count * (timeout_ms / 1000 + 1) + 5
    code, out = run(cmd, timeout=total_timeout)
    times = [float(x) for x in re.findall(
        r"(?:时间|time)[=\s<>]*([\d.]+)\s*ms", out, re.I)]
    if not times:
        return {"min": None, "avg": None, "max": None, "jitter": None,
                "loss_pct": 100.0, "replies": 0, "raw": out}
    loss = max(0.0, (count - len(times)) / count * 100.0)
    avg = sum(times) / len(times)
    return {"min": min(times), "avg": round(avg, 1), "max": max(times),
            "jitter": round(sum(abs(t - avg) for t in times) / len(times), 1),
            "loss_pct": round(loss, 1), "replies": len(times), "raw": out}

def default_gateway():
    """从 ipconfig 解析 IPv4 默认网关，返回 ip 或 None。"""
    code, out = run(["ipconfig"])
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"默认网关|Default Gateway", line) and "IPv4" not in line:
            m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if m:
                return m.group(1)
        # 有的系统把网关跟在 IPv4 行后面
        if re.search(r"IPv4", line):
            for j in range(i, min(i + 4, len(lines))):
                if re.search(r"默认网关|Default Gateway", lines[j]):
                    m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", lines[j])
                    if m:
                        return m.group(1)
    return None

def current_dns():
    """从 ipconfig 解析当前 DNS 服务器列表。"""
    code, out = run(["ipconfig"])
    servers = []
    for line in out.splitlines():
        if re.search(r"DNS 服务器|DNS Servers", line):
            m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if m:
                servers.append(m.group(1))
    return servers

def dns_query(server, host, timeout=3):
    """向指定 DNS 服务器查询 host，返回耗时毫秒；失败返回 None。"""
    try:
        tid = random.randint(0, 0xFFFF)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        q = b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"
        question = q + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            t0 = time.perf_counter()
            s.sendto(header + question, (server, 53))
            s.recvfrom(4096)
            return (time.perf_counter() - t0) * 1000
        finally:
            s.close()
    except Exception:
        return None

def http_ttfb(host, port=443, timeout=5):
    """HTTPS 连接到 host，测到收到首个响应字节的耗时（TTFB，毫秒）；失败返回 None。"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                       "Connection: close\r\nUser-Agent: net-optimizer/1.0\r\n\r\n")
                t0 = time.perf_counter()
                s.sendall(req.encode())
                s.recv(1)
                return (time.perf_counter() - t0) * 1000
    except Exception:
        return None

def _ping_ok(payload_size, target):
    """MTU 探测辅助：以指定负载大小发不分片 ping，成功（收到回复）返回 True。"""
    cmd = ["ping", "-f", "-l", str(payload_size), "-n", "1", "-w", "1500", target]
    code, out = run(cmd, timeout=5)
    return ("来自" in out or "Reply" in out or "TTL" in out.upper())

def mtu_probe(target="223.5.5.5"):
    """二分探测最大不分片 MTU，返回 MTU 值（含 28 字节 IP+ICMP 头）或 None。
    二分后再向上验证几档，消除单次丢包导致的误判。"""
    lo, hi, best = 68, 1472, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if _ping_ok(mid, target):
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    if best:
        for size in range(best + 1, min(best + 4, 1473)):
            if _ping_ok(size, target):
                best = size
            else:
                break
    return best + 28 if best else None

def active_interfaces():
    """返回所有已连接接口的 (名称, 索引, 类型)。"""
    code, out = run(["netsh", "interface", "ipv4", "show", "interfaces"])
    ifs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and re.match(r"^\d+$", parts[0]):
            name = " ".join(parts[3:])
            if "已连接" in line or "Connected" in line:
                ifs.append((name, parts[0], parts[2]))
    return ifs
