# -*- coding: utf-8 -*-
"""测试公共夹具。

**安全底线**：本项目的代码会执行 ``netsh ... set dnsservers``、``powercfg``、
``reg add`` 这类**真实修改用户系统**的命令。因此这里的 autouse 夹具会
拦截 ``netopt.platform.run`` —— 任何忘了注入 fake runner 的测试都会立刻
AssertionError，而不是悄悄改掉跑测试这台机器的网络配置。

**状态隔离**：``netopt.state`` 的路径常量在模块顶层求值，光 patch ``Path.home``
追不到它们，必须直接 patch 模块属性（这是踩过的坑）。这里也用 autouse 夹具做掉，
免得每个测试各写一遍。
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from netopt import platform as platform_mod
from netopt import state as state_mod

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    """读取一份真实抓取的命令输出样本（见 fixtures/SOURCES.md）。"""
    path = FIXTURES / (name if name.endswith((".txt", ".bin")) else name + ".txt")
    if not path.exists():
        raise FileNotFoundError(
            f"样本不存在: {path}。请用 tests/fixtures/ 里已有的真实样本，不要凭空造数据。"
        )
    return path.read_text(encoding="utf-8")


def fixture_bytes(name: str) -> bytes:
    path = FIXTURES / (name if name.endswith(".bin") else name + ".bin")
    return path.read_bytes()


@pytest.fixture(autouse=True)
def _no_real_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    """拦住所有未被注入 fake runner 的真实命令执行。

    不要为了绕过它去 patch ``netopt.platform.subprocess``——那会真的去改本机配置。
    正确做法是给被测函数传 ``run=fake_run(...)``。
    """

    # 签名有意不标注类型：它就是个"抓住一切调用"的陷阱函数
    def _boom(argv, timeout=30.0, **kwargs):
        raise AssertionError(
            "测试中调用了真实的系统命令，已被拦截：\n"
            f"    {argv!r}\n"
            "请给被测函数注入 fake runner，例如 run=fake_run(...)。\n"
            "（本项目的命令会改 DNS / 电源 / 注册表，绝不能在测试里真的执行。）"
        )

    monkeypatch.setattr(platform_mod, "run", _boom)


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """把日志 / 历史 / dev 标志全部重定向到临时目录。"""
    base = tmp_path / "state"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(state_mod, "BASE", base)
    monkeypatch.setattr(state_mod, "HISTORY_FILE", base / "history.json")
    monkeypatch.setattr(state_mod, "DEV_FILE", base / "dev.json")
    monkeypatch.setattr(state_mod, "DNS_BACKUP_FILE", base / "dns-backup.json")
    monkeypatch.setattr(state_mod, "DEV_ON", False, raising=False)
    return base


@pytest.fixture
def fake_run() -> Callable[..., Callable[..., object]]:
    """造一个假 runner：按 argv 前缀匹配返回预设输出。

    用法::

        run = fake_run({("ping",): ("", 0)})          # 简化形式
        run = fake_run({("netsh", "interface"): text})  # 只匹配前缀
    """
    from netopt.platform import CmdResult

    def build(table: dict[tuple[str, ...], object], default: object = None):
        calls: list[list[str]] = []

        def _fake(argv, timeout=30.0, **kwargs):
            argv = list(argv)
            calls.append(argv)
            for prefix, payload in table.items():
                if tuple(argv[: len(prefix)]) == tuple(prefix):
                    if isinstance(payload, CmdResult):
                        return payload
                    if isinstance(payload, tuple) and len(payload) == 2:
                        text, code = payload
                        return CmdResult(argv=argv, code=code, out=text)
                    return CmdResult(argv=argv, code=0, out=str(payload))
            if default is None:
                raise AssertionError(f"fake_run 没有为 {argv!r} 配置返回值")
            return CmdResult(argv=argv, code=0, out=str(default))

        _fake.calls = calls  # type: ignore[attr-defined]
        return _fake

    return build
