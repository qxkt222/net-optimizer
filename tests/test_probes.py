"""platform / probes 测试。

**安全底线**：这里绝不真实执行系统命令。

- probes 的命令一律注入 runner；其中 argv 固定的用 ``fake_run``，
  MTU 探测的 runner 需要按 payload 分支（``fake_run`` 只支持固定前缀匹配），
  用同一批真实样本自行构造。
- ``platform.run`` 自身的测试直接 monkeypatch ``subprocess.run``（仅测试期间），
  conftest 的 autouse 夹具只拦 ``platform.run`` 属性，真正的函数体在这里被单独验证。

样本全部来自 ``tests/fixtures/``（真实抓取，见 SOURCES.md）。
"""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path

import pytest
from conftest import fixture_bytes, fixture_text

from netopt import platform as platform_mod
from netopt import probes
from netopt.platform import CmdResult
from netopt.platform import run as real_run


# ===========================================================================
# platform.run / decode_out / CmdResult
# ===========================================================================
class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_maps_missing_command(monkeypatch: pytest.MonkeyPatch) -> None:
    """D9：命令不存在必须区别于超时，且不是靠 code=-1 让调用方猜。"""

    def _boom(*args, **kwargs):
        raise FileNotFoundError(2, "系统找不到指定的文件")

    monkeypatch.setattr(platform_mod.subprocess, "run", _boom)
    res = real_run(["definitely-not-a-real-program"], timeout=1.0)

    assert res.missing is True
    assert res.timed_out is False
    assert res.ok is False
    assert res.code != 0
    assert res.argv == ["definitely-not-a-real-program"]
    assert isinstance(res.out, str)


def test_run_maps_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """D9：超时必须区别于「命令不存在」，调用方才能显示真实原因。"""

    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="ping", timeout=0.01)

    monkeypatch.setattr(platform_mod.subprocess, "run", _timeout)
    res = real_run(["ping", "1.2.3.4"], timeout=0.01)

    assert res.timed_out is True
    assert res.missing is False
    assert res.ok is False
    assert res.code != 0


def test_run_merges_stdout_stderr_and_decodes_gbk(monkeypatch: pytest.MonkeyPatch) -> None:
    """真实 GBK 样本必须被解出中文；stderr 与 stdout 合并进 out。"""
    raw = fixture_bytes("ipconfig_all_gbk_raw")
    err = "错误信息".encode(encoding="gbk")
    monkeypatch.setattr(platform_mod.subprocess, "run", lambda *a, **k: _FakeProc(0, raw, err))
    res = real_run(["ipconfig", "/all"])

    assert res.ok is True
    assert res.code == 0
    assert "以太网" in res.out
    assert "错误信息" in res.out


@pytest.mark.parametrize(
    ("code", "timed_out", "missing", "expected"),
    [
        (0, False, False, True),
        (0, True, False, False),
        (0, False, True, False),
        (1, False, False, False),
    ],
)
def test_cmdresult_ok_semantics(code: int, timed_out: bool, missing: bool, expected: bool) -> None:
    res = CmdResult(argv=["x"], code=code, out="", timed_out=timed_out, missing=missing)
    assert res.ok is expected


def test_decode_out_utf8_then_gbk() -> None:
    assert platform_mod.decode_out("中文".encode()) == "中文"
    assert "以太网" in platform_mod.decode_out(fixture_bytes("ipconfig_all_gbk_raw"))
    assert platform_mod.decode_out(b"") == ""
    # 两种编码都解不开时用替换字符兜底，不抛异常
    assert "\ufffd" in platform_mod.decode_out(b"\xff\xff\xff")


def test_console_python_swaps_pythonw_for_python(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """D14：pythonw.exe（无控制台）提权会开空窗口，必须换成 python.exe。"""
    (tmp_path / "python.exe").write_text("", encoding="utf-8")
    (tmp_path / "pythonw.exe").write_text("", encoding="utf-8")
    monkeypatch.setattr(platform_mod.sys, "executable", str(tmp_path / "pythonw.exe"))
    assert platform_mod.console_python() == str(tmp_path / "python.exe")


def test_console_python_keeps_pythonw_without_sibling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exe = tmp_path / "pythonw.exe"
    exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(platform_mod.sys, "executable", str(exe))
    assert platform_mod.console_python() == str(exe)


def test_console_python_keeps_regular_interpreter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exe = tmp_path / "python.exe"
    exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(platform_mod.sys, "executable", str(exe))
    assert platform_mod.console_python() == str(exe)


def test_elevate_uses_console_python_and_runas(monkeypatch: pytest.MonkeyPatch) -> None:
    """D14：提权必须用带控制台的解释器，且参数带引号、走 runas。"""
    recorded: dict[str, str] = {}

    def _fake_exec(operation: str, file: str, params: str, cwd: str) -> int:
        recorded.update(operation=operation, file=file, params=params, cwd=cwd)
        return 42

    monkeypatch.setattr(platform_mod, "console_python", lambda: r"C:\Py\python.exe")
    monkeypatch.setattr(platform_mod, "_shell_execute", _fake_exec)

    assert platform_mod.elevate(["fix", "a b"]) is True
    assert recorded["operation"] == "runas"
    assert recorded["file"] == r"C:\Py\python.exe"
    assert '"a b"' in recorded["params"]
    assert "fix" in recorded["params"]


def test_elevate_false_when_uac_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_mod, "_shell_execute", lambda *a: 5)  # ERROR_ACCESS_DENIED
    assert platform_mod.elevate(["auto"]) is False


def test_elevate_exe_override(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}

    def _fake_exec(operation: str, file: str, params: str, cwd: str) -> int:
        seen["file"] = file
        return 42

    monkeypatch.setattr(platform_mod, "console_python", lambda: "SHOULD-NOT-BE-USED")
    monkeypatch.setattr(platform_mod, "_shell_execute", _fake_exec)

    assert platform_mod.elevate(["auto"], exe=r"C:\other\python.exe") is True
    assert seen["file"] == r"C:\other\python.exe"


# ===========================================================================
# probes：argv 固定的命令走 conftest 的 fake_run
# ===========================================================================
def test_ping_parses_replies(fake_run) -> None:
    run = fake_run({("ping",): (fixture_text("ping_ok"), 0)})
    stat = probes.ping("www.baidu.com", count=4, run=run)

    assert stat.target == "www.baidu.com"
    assert stat.replies == 4
    assert stat.loss_pct == 0.0
    assert stat.reachable is True
    assert stat.avg_ms is not None and 20.0 <= stat.avg_ms <= 35.0
    assert stat.raw


def test_ping_timeout_is_100pct_loss(fake_run) -> None:
    run = fake_run({("ping",): (fixture_text("ping_loss100"), 1)})
    stat = probes.ping("198.51.100.1", count=4, run=run)

    assert stat.reachable is False
    assert stat.replies == 0
    assert stat.loss_pct == 100.0
    assert stat.avg_ms is None


def test_ping_missing_binary_does_not_parse_as_reply(fake_run) -> None:
    missing = CmdResult(argv=["ping"], code=-1, out="找不到命令：ping", missing=True)
    run = fake_run({("ping",): missing})
    stat = probes.ping("1.2.3.4", run=run)

    assert stat.reachable is False
    assert stat.loss_pct == 100.0


def test_interfaces_parses_netsh_sample(fake_run) -> None:
    run = fake_run(
        {("netsh", "interface", "ipv4", "show", "interfaces"): fixture_text("netsh_interfaces")}
    )
    ifaces = probes.interfaces(run=run)

    assert len(ifaces) == 8
    by_name = {i.name: i for i in ifaces}
    eth = by_name["以太网"]
    assert (eth.index, eth.mtu, eth.connected) == (2, 1500, True)
    assert by_name["WLAN"].connected is False
    assert by_name["Loopback Pseudo-Interface 1"].is_primary is False


def test_gateway_picks_lowest_metric_active_route(fake_run) -> None:
    """D1：必须取 route 的活动路由里 metric 最小的 192.0.2.1，而不是 198.51.100.1。"""
    run = fake_run({("route", "print"): (fixture_text("route_print_default"), 0)})
    gw = probes.gateway(run=run)

    assert gw is not None
    assert (gw.ip, gw.interface_ip, gw.metric) == ("192.0.2.1", "192.0.2.10", 26)


def test_gateway_none_when_route_missing(fake_run) -> None:
    run = fake_run({("route", "print"): CmdResult(argv=["route"], code=-1, out="", missing=True)})
    assert probes.gateway(run=run) is None


def test_dns_config_prefers_netsh(fake_run) -> None:
    """D3：netsh 才能看到真实静态 DNS（ipconfig 不带 /all 时以太网没有 IPv4 DNS 行）。"""
    run = fake_run(
        {("netsh", "interface", "ipv4", "show", "dnsservers"): fixture_text("netsh_dnsservers")}
    )
    configs = probes.dns_config(run=run)

    eth = next(c for c in configs if c.interface == "以太网")
    assert eth.servers == ["114.114.114.114", "192.0.2.1"]
    assert eth.source == "static"
    # 没有回退：所有命令都必须是 netsh
    assert all(call[0] == "netsh" for call in run.calls)


def test_dns_config_falls_back_to_ipconfig_all(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def run(argv, timeout=30.0, **kwargs):
        argv = list(argv)
        calls.append(argv)
        if argv[0] == "netsh":
            return CmdResult(argv=argv, code=-1, out="", missing=True)
        return CmdResult(argv=argv, code=0, out=fixture_text("ipconfig_all"))

    configs = probes.dns_config(run=run)

    assert any(call[:2] == ["ipconfig", "/all"] for call in calls)
    assert isinstance(configs, list)


def test_primary_interfaces_only_the_default_route_adapter(fake_run) -> None:
    """D11：只有承载默认路由的「以太网」该被改 DNS，Example VPN 不能碰。"""
    run = fake_run(
        {
            ("route", "print", "-4", "0.0.0.0"): (fixture_text("route_print_default"), 0),
            ("ipconfig", "/all"): (fixture_text("ipconfig_all"), 0),
            ("netsh", "interface", "ipv4", "show", "interfaces"): fixture_text("netsh_interfaces"),
        }
    )
    ifaces = probes.primary_interfaces(run=run)

    assert [i.name for i in ifaces] == ["以太网"]


def test_primary_interfaces_empty_without_default_route(fake_run) -> None:
    run = fake_run({("route", "print"): CmdResult(argv=["route"], code=1, out="")})
    assert probes.primary_interfaces(run=run) == []
    assert len(run.calls) == 1  # 没有默认路由就不该再跑别的命令


# ===========================================================================
# dns_query / http_ttfb（socket 直连，用假 socket 验证协议校验与容错）
# ===========================================================================
class _FakeUdpSocket:
    def __init__(self, reply) -> None:
        self._reply = reply
        self.sent: bytes = b""

    def settimeout(self, timeout) -> None:
        self.timeout = timeout

    def sendto(self, data: bytes, addr) -> None:
        self.sent = data

    def recvfrom(self, size: int):
        return self._reply(self.sent), ("127.0.0.1", 53)

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False


def _dns_reply(tid_delta: int = 0, flags: int = 0x8180) -> bytes:
    def _build(sent: bytes) -> bytes:
        tid = struct.unpack(">H", sent[:2])[0]
        return struct.pack(">HHHHHH", (tid + tid_delta) & 0xFFFF, flags, 1, 1, 0, 0)

    return _build


def _install_udp(monkeypatch: pytest.MonkeyPatch, sock: object) -> None:
    monkeypatch.setattr(probes.socket, "socket", lambda *a, **k: sock)


def test_dns_query_accepts_matching_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = _FakeUdpSocket(_dns_reply())
    _install_udp(monkeypatch, sock)

    elapsed = probes.dns_query("223.5.5.5", "www.baidu.com", timeout=1.0)

    assert elapsed is not None and elapsed >= 0.0
    # 发出的必须是一条格式正确的标准 A 查询（flags=0x0100，尾部 QTYPE/QCLASS=1/1）
    assert len(sock.sent) > 12
    assert struct.unpack(">H", sock.sent[2:4])[0] == 0x0100
    assert sock.sent[-4:] == struct.pack(">HH", 1, 1)


def test_dns_query_rejects_wrong_transaction_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_udp(monkeypatch, _FakeUdpSocket(_dns_reply(tid_delta=1)))
    assert probes.dns_query("223.5.5.5", "www.baidu.com", timeout=1.0) is None


def test_dns_query_rejects_non_response_packet(monkeypatch: pytest.MonkeyPatch) -> None:
    """QR=0 是查询不是应答，不能当成有效回复。"""
    _install_udp(monkeypatch, _FakeUdpSocket(_dns_reply(flags=0x0100)))
    assert probes.dns_query("223.5.5.5", "www.baidu.com", timeout=1.0) is None


def test_dns_query_returns_none_on_socket_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*a, **k):
        raise OSError("network unreachable")

    monkeypatch.setattr(probes.socket, "socket", _raise)
    assert probes.dns_query("223.5.5.5", "www.baidu.com") is None


class _FakeTls:
    def sendall(self, data: bytes) -> None:
        self.sent = data

    def recv(self, size: int) -> bytes:
        return b"H"

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False


class _FakeCtx:
    def wrap_socket(self, sock, server_hostname=None):
        return _FakeTls()


class _FakeSock:
    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False


def test_http_ttfb_returns_ms(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes.ssl, "create_default_context", lambda: _FakeCtx())
    monkeypatch.setattr(probes.socket, "create_connection", lambda *a, **k: _FakeSock())

    elapsed = probes.http_ttfb("www.baidu.com", timeout=1.0)

    assert elapsed is not None and elapsed >= 0.0


def test_http_ttfb_returns_none_on_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(probes.socket, "create_connection", _raise)
    assert probes.http_ttfb("www.baidu.com") is None


# ===========================================================================
# mtu() —— D15 的主战场
# ===========================================================================
_DF_OK = fixture_text("ping_df_ok")  # 真实样本：payload 1464 通
_DF_FAIL = fixture_text("ping_df_fail")  # 真实样本：payload 1472 报「需要拆分数据包但是设置 DF」
_LOSS = fixture_text("ping_loss100")  # 真实样本：请求超时（不确定信号）

_MTU_LIMIT = 1464  # 本机真值：1464 全通、1465 起 0/8 通过 → MTU 1492


def _payload_of(argv: list[str]) -> int:
    return int(argv[argv.index("-l") + 1])


def _mtu_runner(limit: int = _MTU_LIMIT, upper: str = "df", first_uncertain: bool = False):
    """按 payload 分支的假 ping（fixture 只支持固定 argv 前缀，无法按 -l 分支）。

    ``limit`` 及以下返回真实的「通」样本；以上默认返回真实的 DF 失败样本，
    ``upper="timeout"`` 时返回真实的超时样本（不确定信号）。
    """
    calls: list[list[str]] = []
    seen_first = False

    def _run(argv, timeout=30.0, **kwargs):
        nonlocal seen_first
        argv = list(argv)
        calls.append(argv)
        payload = _payload_of(argv)
        if first_uncertain and not seen_first:
            seen_first = True
            return CmdResult(argv=argv, code=1, out=_LOSS)
        if payload <= limit:
            return CmdResult(argv=argv, code=0, out=_DF_OK.replace("1464", str(payload)))
        if upper == "timeout":
            return CmdResult(argv=argv, code=1, out=_LOSS)
        return CmdResult(argv=argv, code=1, out=_DF_FAIL.replace("1472", str(payload)))

    _run.calls = calls  # type: ignore[attr-defined]
    return _run


def test_mtu_finds_pppoe_1492() -> None:
    """D15：本机真值 MTU=1492（payload 1464 通 / 1465 不通），必须稳定得出。"""
    run = _mtu_runner()
    result = probes.mtu(run=run)

    assert result.payload == 1464
    assert result.mtu == 1492
    assert result.verified is True
    assert result.is_pppoe() is True
    # 性能守卫：每个点一次 ping，总次数不该接近预算上限
    assert len(run.calls) <= 25, f"探测次数过多: {len(run.calls)}"


def test_mtu_standard_ethernet_when_all_payloads_pass() -> None:
    """全程可通（如标准以太网 1500）：报 1500 且 verified=True。"""
    run = _mtu_runner(limit=1472)
    result = probes.mtu(run=run)

    assert result.payload == 1472
    assert result.mtu == 1500
    assert result.verified is True
    assert result.is_standard_ethernet() is True


def test_mtu_stable_across_repeated_runs() -> None:
    """旧实现 7 次里有 1 次返回 1495；新实现同一输入必须次次一致。"""
    results = [probes.mtu(run=_mtu_runner()) for _ in range(5)]
    assert {(r.payload, r.mtu, r.verified) for r in results} == {(1464, 1492, True)}


def test_mtu_retries_uncertain_probe() -> None:
    """首次探测返回超时（不确定）时必须重试同一 payload，而不是当成失败。"""
    run = _mtu_runner(first_uncertain=True)
    result = probes.mtu(run=run)

    assert result.mtu == 1492
    assert len(run.calls) >= 2
    assert run.calls[0] == run.calls[1], "不确定结果没有重试同一点位"


def test_mtu_timeout_at_upper_bound_is_not_a_pass() -> None:
    """D15：1465 起是超时（不确定）而非 DF 时，不能把它当通过（旧实现会抬高到 1495）。"""
    run = _mtu_runner(upper="timeout")
    result = probes.mtu(run=run)

    assert result.payload == 1464
    assert result.mtu == 1492
    assert result.verified is False  # 上界没能确定，标注「仅供参考」


def test_mtu_unreachable_returns_empty_and_bails_early() -> None:
    run = _mtu_runner(limit=0, upper="timeout")  # 连 68 都不通
    result = probes.mtu(run=run)

    assert result.found is False
    assert result.mtu is None
    assert result.payload is None
    assert len(run.calls) <= 4, "不可达时应尽早退出"


def test_mtu_ping_missing_returns_empty(fake_run) -> None:
    run = fake_run(
        {("ping",): CmdResult(argv=["ping"], code=-1, out="找不到命令：ping", missing=True)}
    )
    result = probes.mtu(run=run)
    assert result.found is False
