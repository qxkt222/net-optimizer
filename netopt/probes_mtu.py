# -*- coding: utf-8 -*-
"""MTU 探测（v2）—— 预算内的 DF 二分 + 边界确认。

与 v1 :func:`netopt.probes.mtu` 的判定逻辑一致（三态 ``ping_reply_ok``、
不确定重试、边界复查），区别只有一个：**所有循环都受总的截止时间约束**。

v1 最坏会发 40 次 ping 且没有总预算，慢链路或丢包时会把一次 ``status``
拖到十几秒。这里的预算默认 8 秒，取 ``min(max_seconds, ctx 剩余时间)``；
一旦到期立即停止，返回**已经得到**的结果并标 ``verified=False``，
同时通过 ``ctx.record_error`` 记一条 ``timeout``，绝不静默吞掉。

不打印、不读写文件；命令执行器由 ``run`` 注入。
"""

from __future__ import annotations

import time

from netopt import parsers, platform
from netopt.domain.codes import ProbeErrorCode
from netopt.models import MtuResult
from netopt.platform import Runner
from netopt.probes import ProbeContext

# 探测参数（与 v1 保持一致，见 netopt/probes.py）-------------------------------
_MTU_OVERHEAD = 28  # IPv4 头 20 + ICMP 头 8
_MTU_MIN_PAYLOAD = 68  # 再小的 payload 没有探测意义
_MTU_MAX_PAYLOAD = 1472  # 1500 - 28
_MTU_ATTEMPTS = 2  # 单个点位的尝试次数（首次 + 1 次重试）
_MTU_CONFIRM = 3  # 边界下界复查次数（必须连续确定通过）
_MTU_MAX_PROBES = 40  # 全局次数上限，防病态 runner 下无限探测
_MTU_PING_TIMEOUT_MS = 1000  # 单次 ping 等待回复的毫秒数
_PING_TIMEOUT_CAP = 5.0  # 单次子进程超时上限（秒）


def probe(
    target: str = "223.5.5.5",
    *,
    ctx: ProbeContext | None = None,
    run: Runner | None = None,
    max_seconds: float = 8.0,
) -> MtuResult:
    """在预算内二分探测路径 MTU，返回 ``MtuResult``。

    - 判定复用 :func:`netopt.parsers.ping_reply_ok` 的三态语义：
      ``True`` 确定通过、``False`` 确定包太大、``None`` 不确定（重试）。
    - 二分收敛后复查边界：``best`` 连续确定通过 ``_MTU_CONFIRM`` 次，
      ``best + 1`` 至少一次确定失败，才置 ``verified=True``。
    - 预算取 ``min(max_seconds, ctx 剩余时间)``；未传 ``ctx`` 时按
      ``max_seconds`` 自建一个。预算耗尽立即停止，返回已得结果 +
      ``verified=False``，并在上下文里记一条 ``timeout``。
    - 每次 ping 的 ``timeout`` 取 ``min(5.0, 剩余预算)``，不会越过总截止时间。
    - 目标完全不可达（拿不到任何确定信号）时返回全 ``None`` 的 ``MtuResult``。
    """
    run = run if run is not None else platform.run
    context = ctx if ctx is not None else ProbeContext.with_budget(max_seconds)

    # 预算同时受本次调用上限与上下文剩余时间约束；已到期则预算为 0。
    budget = min(max(0.0, max_seconds), context.remaining())
    deadline = time.monotonic() + budget

    timed_out = False
    uncertain = False
    calls = 0
    best: int | None = None

    def remaining() -> float:
        """本次探测还剩多少秒（已扣除上下文自身的剩余时间）。"""
        return max(0.0, deadline - time.monotonic())

    def expired() -> bool:
        """本次预算或上下文预算任一耗尽即为到期。"""
        return remaining() <= 0.0 or context.expired()

    def stop() -> bool:
        """检查截止时间；首次到期时记录一条 timeout，之后直接返回。"""
        nonlocal timed_out
        if timed_out:
            return True
        if not expired():
            return False
        timed_out = True
        context.record_error(
            ProbeErrorCode.TIMEOUT,
            "mtu",
            f"MTU 探测超出预算（{budget:g} 秒），结果未验证",
            retryable=True,
        )
        return True

    def ping_once(payload: int) -> bool | None:
        """单点探测；不确定的报文自动重试，重试仍不确定才返回 None。"""
        nonlocal calls, uncertain
        for _ in range(_MTU_ATTEMPTS):
            if stop():
                return None
            if calls >= _MTU_MAX_PROBES:
                uncertain = True
                return None
            wait = remaining()
            if wait <= 0.0:
                stop()
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
                timeout=min(_PING_TIMEOUT_CAP, wait),
            )
            # 命令即使返回了，只要已经越过截止时间就立即停止，不再采信结果。
            if stop():
                return None
            if res.missing or res.timed_out:
                continue
            verdict = parsers.ping_reply_ok(res.out, res.code)
            if verdict is not None:
                return verdict
        uncertain = True
        return None

    def search(lo: int, hi: int) -> int | None:
        """在 [lo, hi] 内二分；返回目前确定可用的最大 payload。"""
        nonlocal best, uncertain
        while lo <= hi and not stop():
            if calls >= _MTU_MAX_PROBES:
                uncertain = True
                break
            mid = (lo + hi) // 2
            if ping_once(mid) is True:
                best = mid
                lo = mid + 1
            else:
                # False（DF，确定太大）与 None（不确定，保守）都收窄上界
                hi = mid - 1
        return best

    # 先确认最小 payload 能通，否则视为目标不可达 / 测不出。
    if ping_once(_MTU_MIN_PAYLOAD) is not True:
        return MtuResult()

    if search(_MTU_MIN_PAYLOAD + 1, _MTU_MAX_PAYLOAD) is None:
        return MtuResult()

    verified = False
    for _ in range(3):
        if best is None or stop():
            break

        # 下界确认：best 必须连续 N 次**确定**通过
        outcome = "pass"
        for _ in range(_MTU_CONFIRM):
            verdict = ping_once(best)
            if verdict is False:
                outcome = "lower"  # 与二分结论矛盾：best 其实太大，向下纠错
                break
            if verdict is not True:
                outcome = "unknown"
                break
            if stop():
                break
        if stop():
            break
        if outcome == "lower":
            best = search(_MTU_MIN_PAYLOAD + 1, best - 1)
            if best is None:
                return MtuResult()
            continue
        if outcome != "pass":
            break

        # 上界确认：best + 1 需要一次确定失败；若竟然通过，边界其实更高
        if best >= _MTU_MAX_PAYLOAD:
            verified = True
            break
        verdict = ping_once(best + 1)
        if stop():
            break
        if verdict is False:
            verified = True
            break
        if verdict is True:
            best += 1
            continue
        break  # None：上界不确定

    if best is None:
        return MtuResult()
    if timed_out or uncertain:
        verified = False
    return MtuResult(mtu=best + _MTU_OVERHEAD, payload=best, verified=verified)
