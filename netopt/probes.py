"""探测层 —— 组合 :mod:`netopt.platform` 与 :mod:`netopt.parsers`，产出领域数据。

**依赖注入约定**（BRIEF §5）：所有会执行命令的函数都接受 ``run`` 参数，默认值在
*调用时*解析为 ``platform.run``（不能写成 def 默认参数，否则测试 monkeypatch 追不到，
conftest 的拦截夹具也会失效）。

不执行子进程的探测（``dns_query`` / ``http_ttfb``）直接走 socket，无需注入。
"""

from __future__ import annotations

import random
import socket
import ssl
import struct
import time

from netopt import parsers, platform
from netopt.models import DnsConfig, Gateway, Interface, MtuResult, PingStat
from netopt.platform import Runner

# MTU 探测参数 ---------------------------------------------------------------
_MTU_OVERHEAD = 28  # IPv4 头 20 + ICMP 头 8
_MTU_MIN_PAYLOAD = 68  # 再小的 payload 没有探测意义
_MTU_MAX_PAYLOAD = 1472  # 1500 - 28
_MTU_ATTEMPTS = 2  # 单个点位的尝试次数（首次 + 1 次重试）
_MTU_CONFIRM = 3  # 边界下界复查次数（必须连续确定通过）
_MTU_MAX_PROBES = 40  # 全局预算，防病态输入下无限探测
_MTU_PING_TIMEOUT_MS = 1000  # 单次 ping 等待回复的毫秒数


def ping(
    target: str,
    count: int = 4,
    timeout_ms: int = 1000,
    run: Runner | None = None,
) -> PingStat:
    """Ping 目标并返回往返统计。"""
    run = run if run is not None else platform.run
    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), target]
    # 与旧实现一致：给子进程留出 count 次超时 + 启动开销的余量
    total_timeout = count * (timeout_ms / 1000 + 1) + 5
    res = run(cmd, timeout=total_timeout)
    if res.missing or res.timed_out:
        return PingStat(target=target, loss_pct=100.0, replies=0, raw=res.out)
    return parsers.parse_ping(res.out, target=target, count=count, code=res.code)


def interfaces(run: Runner | None = None) -> list[Interface]:
    """所有 IPv4 接口（netsh interface ipv4 show interfaces）。"""
    run = run if run is not None else platform.run
    res = run(["netsh", "interface", "ipv4", "show", "interfaces"])
    if res.missing:
        return []
    return parsers.parse_netsh_interfaces(res.out)


def gateway(run: Runner | None = None) -> Gateway | None:
    """IPv4 默认网关（metric 最小的活动路由）。

    旧实现取 ``ipconfig`` 里第一个网关，会选到 metric 9257 的 Example VPN
    虚拟网卡（缺陷 D1）；这里改用 ``route print -4`` 的活动路由段。
    """
    run = run if run is not None else platform.run
    res = run(["route", "print", "-4", "0.0.0.0"])
    if res.missing:
        return None
    return parsers.parse_route_default(res.out)


def dns_config(run: Runner | None = None) -> list[DnsConfig]:
    """各接口 DNS 配置。

    优先 ``netsh interface ipv4 show dnsservers``（能区分 static/dhcp，且能看到
    ipconfig 不带 /all 时隐藏的静态 DNS，缺陷 D3）；命令失败才回退 ``ipconfig /all``。
    """
    run = run if run is not None else platform.run
    res = run(["netsh", "interface", "ipv4", "show", "dnsservers"])
    configs: list[DnsConfig] = []
    if not res.missing and res.code == 0:
        configs = parsers.parse_netsh_dnsservers(res.out)
    if configs:
        return configs
    fallback = run(["ipconfig", "/all"])
    if fallback.missing:
        return []
    return parsers.parse_ipconfig_dns(fallback.out)


def primary_interfaces(run: Runner | None = None) -> list[Interface]:
    """承载**默认路由**的接口。

    这是 ``fix dns`` 唯一该改 DNS 的对象（缺陷 D11：旧实现无差别覆盖所有已连接
    接口，会打断内网/公司 split-DNS）。用 route 的接口 IP 去匹配 ipconfig 的
    适配器名 → IPv4 映射，再对上 netsh 的接口列表。
    """
    run = run if run is not None else platform.run
    gw = gateway(run)
    if gw is None:
        return []
    res = run(["ipconfig", "/all"])
    if res.missing:
        return []
    addresses = parsers.parse_ipconfig_addresses(res.out)
    names = {name for name, ip in addresses.items() if ip == gw.interface_ip}
    if not names:
        return []
    return [iface for iface in interfaces(run) if iface.name in names]


def dns_query(server: str, host: str, timeout: float = 3.0) -> float | None:
    """直接向 ``server`` 发一条 A 查询，返回耗时毫秒；失败返回 None。

    自组 DNS 报文（保留旧实现行为），但校验应答的事务 ID 与 QR 位，
    不把端口上收到的无关 UDP 包当成有效应答。
    """
    try:
        tid = random.randint(0, 0xFFFF)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        question = (
            b"".join(bytes([len(p)]) + p.encode() for p in host.split("."))
            + b"\x00"
            + struct.pack(">HH", 1, 1)
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            started = time.perf_counter()
            sock.sendto(header + question, (server, 53))
            data, _addr = sock.recvfrom(4096)
            elapsed = (time.perf_counter() - started) * 1000.0
        if len(data) < 12:
            return None
        reply_id, flags = struct.unpack(">HH", data[:4])
        if reply_id != tid or not flags & 0x8000:
            return None
        return elapsed
    except Exception:
        return None


def http_ttfb(host: str, port: int = 443, timeout: float = 5.0) -> float | None:
    """TLS 建连后发 GET，返回首个响应字节的耗时（毫秒）；失败返回 None。"""
    try:
        ctx = ssl.create_default_context()
        with (
            socket.create_connection((host, port), timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls,
        ):
            request = (
                f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                "Connection: close\r\nUser-Agent: net-optimizer/1.0\r\n\r\n"
            )
            started = time.perf_counter()
            tls.sendall(request.encode())
            tls.recv(1)
            return (time.perf_counter() - started) * 1000.0
    except Exception:
        return None


def mtu(target: str = "223.5.5.5", run: Runner | None = None) -> MtuResult:
    """二分探测路径 MTU（DF ping），返回 ``MtuResult``。

    与旧 ``netlib.mtu_probe`` 的区别（缺陷 D15）：

    - 用 :func:`netopt.parsers.ping_reply_ok` 的三态结果驱动，**区分**
      「DF 包太大」（``False``，确定上界）与「超时」（``None``，不确定）；
      不确定会重试，重试仍不确定就不计入结论并置 ``verified=False``。
    - 收敛后复查边界：``best`` 必须连续确定通过 ``_MTU_CONFIRM`` 次，
      ``best+1`` 至少一次确定失败；期间发现 ``best`` 偏大/偏小会反向修正。
    - 目标完全不可达（拿不到任何确定信号）时返回全 None 的 ``MtuResult``。
    """
    run = run if run is not None else platform.run
    uncertain = False
    calls = 0

    def probe(payload: int) -> bool | None:
        """单点探测；不确定的报文自动重试，重试仍不确定才返回 None。"""
        nonlocal calls, uncertain
        for _ in range(_MTU_ATTEMPTS):
            if calls >= _MTU_MAX_PROBES:
                uncertain = True
                return None
            calls += 1
            res = run(
                [
                    "ping",
                    "-f",
                    "-l",
                    str(payload),
                    "-n",
                    "1",
                    "-w",
                    str(_MTU_PING_TIMEOUT_MS),
                    target,
                ],
                timeout=5.0,
            )
            if res.missing or res.timed_out:
                continue
            verdict = parsers.ping_reply_ok(res.out, res.code)
            if verdict is not None:
                return verdict
        uncertain = True
        return None

    def search(lo: int, hi: int, best: int | None) -> int | None:
        while lo <= hi and calls < _MTU_MAX_PROBES:
            mid = (lo + hi) // 2
            if probe(mid) is True:
                best = mid
                lo = mid + 1
            else:
                # False（DF，确定太大）与 None（不确定，保守）都收窄上界
                hi = mid - 1
        return best

    # 先确认最小 payload 能通，否则视为目标不可达 / 测不出
    if probe(_MTU_MIN_PAYLOAD) is not True:
        return MtuResult()

    best = search(_MTU_MIN_PAYLOAD + 1, _MTU_MAX_PAYLOAD, _MTU_MIN_PAYLOAD)
    if best is None:
        return MtuResult()

    verified = False
    for _ in range(3):
        # 下界确认：best 必须连续 N 次**确定**通过
        outcome = "pass"
        for _ in range(_MTU_CONFIRM):
            verdict = probe(best)
            if verdict is False:
                outcome = "lower"  # 与二分结论矛盾：best 其实太大，向下纠错
                break
            if verdict is not True:
                outcome = "unknown"
                break
        if outcome == "lower":
            best = search(_MTU_MIN_PAYLOAD + 1, best - 1, _MTU_MIN_PAYLOAD)
            if best is None:
                return MtuResult()
            continue
        if outcome == "unknown":
            break

        # 上界确认：best+1 需要一次确定失败；若竟然通过，边界其实更高
        if best >= _MTU_MAX_PAYLOAD:
            verified = True
            break
        verdict = probe(best + 1)
        if verdict is False:
            verified = True
            break
        if verdict is True:
            best += 1
            continue
        break  # None：上界不确定

    if uncertain:
        verified = False
    return MtuResult(mtu=best + _MTU_OVERHEAD, payload=best, verified=verified)
