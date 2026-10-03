# -*- coding: utf-8 -*-
"""fix 编排层测试（D5 / D9 / D11）。

安全：所有命令都经由注入的 fake runner 执行，conftest 的 autouse 夹具会拦住
任何漏注入的真实调用。``netsh ... set/add dnsservers`` / ``powercfg`` / ``reg add``
在这里**只被断言 argv**，绝不真实执行。

预期 argv 全部是按旧实现参数与需求书写**独立**的字面量，不从被测函数取值。
"""

from __future__ import annotations

import json

import pytest
from conftest import fixture_text

from netopt import fix, probes, state
from netopt import platform as platform_mod
from netopt.platform import CmdResult

_SET_DNS = ("netsh", "interface", "ipv4", "set", "dnsservers")
_ADD_DNS = ("netsh", "interface", "ipv4", "add", "dnsservers")

# 旧实现参数照抄（BRIEF：参数照旧），作为独立预期值
_TCP_RULES = [
    ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
    ["netsh", "int", "tcp", "set", "global", "ecncapability=disabled"],
    ["netsh", "int", "tcp", "set", "global", "rss=enabled"],
    ["netsh", "int", "tcp", "set", "global", "nonsackrttresiliency=disabled"],
]
_POWER_RULES = [
    [
        "powercfg",
        "/setacvalueindex",
        "SCHEME_CURRENT",
        "2a737441-1930-4402-8d77-b2bebba308a3",
        "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
        "0",
    ],
    [
        "powercfg",
        "/setdcvalueindex",
        "SCHEME_CURRENT",
        "2a737441-1930-4402-8d77-b2bebba308a3",
        "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
        "0",
    ],
    ["powercfg", "/setactive", "SCHEME_CURRENT"],
    [
        "reg",
        "add",
        r"HKLM\SYSTEM\CurrentControlSet\Services\USB",
        "/v",
        "DisableSelectiveSuspend",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ],
]

#: 以太网的 DNS 已经是目标值（真实 netsh 输出格式，接口名与列宽照 fixture）
_ALREADY_TARGET_DNS = """接口 "以太网" 的配置
    静态配置的 DNS 服务器:            223.5.5.5
                                          119.29.29.29
    用哪个前缀注册:                   只是主要
"""


def _mod_calls(run) -> list[list[str]]:
    """只挑出会修改 DNS 配置的命令，用于逐条断言 argv 顺序。"""
    return [call for call in run.calls if tuple(call[:5]) in (_SET_DNS, _ADD_DNS)]


def _fix_runner(fake_run, dns_text: str | None = None):
    """覆盖 fix_dns/tcp/power 全部探测与执行命令的假 runner。"""
    table = {
        ("route", "print", "-4", "0.0.0.0"): (fixture_text("route_print_default"), 0),
        ("ipconfig", "/all"): (fixture_text("ipconfig_all"), 0),
        ("ipconfig", "/flushdns"): ("", 0),
        ("netsh", "interface", "ipv4", "show", "interfaces"): fixture_text("netsh_interfaces"),
        ("netsh", "interface", "ipv4", "show", "dnsservers"): (
            dns_text if dns_text is not None else fixture_text("netsh_dnsservers")
        ),
        _SET_DNS: ("", 0),
        _ADD_DNS: ("", 0),
        ("ping",): (fixture_text("ping_ok"), 0),
        ("netsh", "int", "tcp", "set", "global"): ("", 0),
        ("powercfg",): ("", 0),
        ("reg",): ("", 0),
    }
    return fake_run(table)


def _write_backup(entries: dict[str, dict]) -> None:
    state.DNS_BACKUP_FILE.write_text(
        json.dumps({"created": "2026-10-03 12:00:00", "interfaces": entries}, ensure_ascii=False),
        encoding="utf-8",
    )


def _read_backup() -> dict:
    return json.loads(state.DNS_BACKUP_FILE.read_text(encoding="utf-8"))


# ===========================================================================
# D11：备份先于修改、只动 primary 接口
# ===========================================================================
def test_fix_dns_backs_up_original_before_first_change(fake_run) -> None:
    """备份必须**先于任何 DNS 修改命令**完成并落盘，且记录的是原值。"""
    run = _fix_runner(fake_run)
    seen: list[dict] = []

    def spy(argv, timeout=30.0, **kwargs):
        if not seen and tuple(argv[:5]) in (_SET_DNS, _ADD_DNS):
            seen.append(_read_backup())
        return run(argv, timeout=timeout, **kwargs)

    assert fix.fix_dns(run=spy) is True

    assert seen, "发出修改命令前没有写备份"
    entry = seen[0]["interfaces"]["以太网"]
    assert entry["servers"] == ["114.114.114.114", "192.0.2.1"]
    assert entry["source"] == "static"
    assert entry["time"]

    # 备份文件在测试结束后仍然存在且只包含被处理的 primary 接口
    assert set(_read_backup()["interfaces"]) == {"以太网"}

    # argv 逐条断言：set primary + add index=2，顺序不能反
    assert _mod_calls(run) == [
        [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            "name=以太网",
            "static",
            "223.5.5.5",
            "primary",
        ],
        [
            "netsh",
            "interface",
            "ipv4",
            "add",
            "dnsservers",
            "name=以太网",
            "119.29.29.29",
            "index=2",
        ],
    ]


def test_fix_dns_never_touches_non_primary_interfaces(fake_run) -> None:
    """旧行为无差别覆盖所有已连接接口；本机 Example VPN/WLAN/vEthernet 都不能碰。"""
    run = _fix_runner(fake_run)
    assert fix.fix_dns(run=run) is True

    assert {call[5] for call in _mod_calls(run)} == {"name=以太网"}
    combined = "\n".join(" ".join(call) for call in run.calls)
    assert "Example VPN" not in combined
    assert "vEthernet" not in combined
    assert "Loopback" not in combined
    assert "WLAN" not in combined


def test_fix_dns_without_default_route_changes_nothing(fake_run) -> None:
    """没有默认路由 → 找不到 primary 接口，一条修改命令都不发、不建备份。"""
    run = fake_run({("route", "print", "-4", "0.0.0.0"): ("", 0)})
    assert fix.fix_dns(run=run) is False

    assert _mod_calls(run) == []
    assert ["ipconfig", "/flushdns"] not in run.calls
    assert state.DNS_BACKUP_FILE.exists() is False


def test_fix_dns_is_idempotent_but_still_backs_up(fake_run) -> None:
    """D11：已是目标 DNS → 不再重复设置；但仍必须备份当前值。"""
    run = _fix_runner(fake_run, dns_text=_ALREADY_TARGET_DNS)
    assert fix.fix_dns(run=run) is True

    assert _mod_calls(run) == []
    assert ["ipconfig", "/flushdns"] in run.calls  # 清缓存不是 DNS 配置修改，仍执行
    assert _read_backup()["interfaces"]["以太网"] == {
        "servers": ["223.5.5.5", "119.29.29.29"],
        "source": "static",
        "time": _read_backup()["interfaces"]["以太网"]["time"],
    }


def test_fix_dns_keeps_original_backup_across_repeated_runs(fake_run) -> None:
    """重复 fix dns 不能把备份覆盖成「已改过的值」，否则还原等于没还原。"""
    _write_backup(
        {
            "以太网": {
                "servers": ["114.114.114.114", "192.0.2.1"],
                "source": "static",
                "time": "2026-10-03 12:00:00",
            }
        }
    )
    run = _fix_runner(fake_run, dns_text=_ALREADY_TARGET_DNS)
    assert fix.fix_dns(run=run) is True

    entry = _read_backup()["interfaces"]["以太网"]
    assert entry["servers"] == ["114.114.114.114", "192.0.2.1"]
    assert entry["time"] == "2026-10-03 12:00:00"


def test_fix_dns_aborts_when_backup_cannot_be_written(
    fake_run, monkeypatch, tmp_path, capsys
) -> None:
    """备份写不进去就绝不动系统：不 flush、不 set/add。"""
    monkeypatch.setattr(state, "DNS_BACKUP_FILE", tmp_path / "no-such-dir" / "dns-backup.json")
    run = _fix_runner(fake_run)

    assert fix.fix_dns(run=run) is False
    assert _mod_calls(run) == []
    assert ["ipconfig", "/flushdns"] not in run.calls
    assert "无法写入" in capsys.readouterr().out


# ===========================================================================
# D11：--restore
# ===========================================================================
def test_restore_static_replays_set_primary_then_indexed_adds(fake_run) -> None:
    _write_backup(
        {
            "以太网": {
                "servers": ["114.114.114.114", "192.0.2.1", "223.6.6.6"],
                "source": "static",
                "time": "2026-10-03 12:00:00",
            }
        }
    )
    run = fake_run({}, default=("", 0))
    assert fix.fix_dns(run=run, restore=True) is True

    assert run.calls == [
        [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            "name=以太网",
            "static",
            "114.114.114.114",
            "primary",
        ],
        [
            "netsh",
            "interface",
            "ipv4",
            "add",
            "dnsservers",
            "name=以太网",
            "192.0.2.1",
            "index=2",
        ],
        ["netsh", "interface", "ipv4", "add", "dnsservers", "name=以太网", "223.6.6.6", "index=3"],
    ]


@pytest.mark.parametrize("source", ["dhcp", "none"])
def test_restore_dhcp_or_none_sets_source_dhcp(fake_run, source) -> None:
    _write_backup({"WLAN": {"servers": [], "source": source, "time": "2026-10-03 12:00:00"}})
    run = fake_run({}, default=("", 0))
    assert fix.fix_dns(run=run, restore=True) is True

    assert run.calls == [
        ["netsh", "interface", "ipv4", "set", "dnsservers", "name=WLAN", "source=dhcp"]
    ]


def test_restore_without_backup_reports_clearly(fake_run, capsys) -> None:
    run = fake_run({}, default=("", 0))
    assert fix.fix_dns(run=run, restore=True) is False

    assert run.calls == []
    assert "没有可还原的备份" in capsys.readouterr().out


def test_restore_with_corrupt_backup_reports_clearly(fake_run, capsys) -> None:
    state.DNS_BACKUP_FILE.write_text("{ 这不是 json", encoding="utf-8")
    run = fake_run({}, default=("", 0))
    assert fix.fix_dns(run=run, restore=True) is False

    assert run.calls == []
    assert "没有可还原的备份" in capsys.readouterr().out


def test_restore_reports_each_interface_and_stops_on_set_failure(fake_run, capsys) -> None:
    """逐接口报告：以太网 set 失败 → 不再发它的 add，且整体返回 False；WLAN 照常还原。"""
    _write_backup(
        {
            "以太网": {
                "servers": ["114.114.114.114", "192.0.2.1"],
                "source": "static",
                "time": "2026-10-03 12:00:00",
            },
            "WLAN": {"servers": [], "source": "dhcp", "time": "2026-10-03 12:00:00"},
        }
    )
    run = fake_run(
        {("netsh", "interface", "ipv4", "set", "dnsservers", "name=以太网"): ("拒绝访问", 1)},
        default=("", 0),
    )
    assert fix.fix_dns(run=run, restore=True) is False

    assert run.calls == [
        [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            "name=以太网",
            "static",
            "114.114.114.114",
            "primary",
        ],
        ["netsh", "interface", "ipv4", "set", "dnsservers", "name=WLAN", "source=dhcp"],
    ]
    out = capsys.readouterr().out
    assert "✗ 失败" in out
    assert "✓ 完成" in out


# ===========================================================================
# cmd_fix 入口
# ===========================================================================
def test_cmd_fix_unknown_target_reports_and_does_nothing(fake_run, capsys) -> None:
    run = fake_run({}, default=("", 0))
    assert fix.cmd_fix("nope", run=run) is False
    assert run.calls == []
    assert "未知修复项" in capsys.readouterr().out


def test_cmd_fix_dns_restore_is_wired(fake_run) -> None:
    _write_backup({"WLAN": {"servers": [], "source": "dhcp", "time": "2026-10-03 12:00:00"}})
    run = fake_run({}, default=("", 0))
    assert fix.cmd_fix("dns", restore=True, run=run) is True

    assert run.calls == [
        ["netsh", "interface", "ipv4", "set", "dnsservers", "name=WLAN", "source=dhcp"]
    ]


def test_cmd_fix_restore_rejected_for_non_dns(fake_run, capsys) -> None:
    run = fake_run({}, default=("", 0))
    assert fix.cmd_fix("tcp", restore=True, run=run) is False
    assert run.calls == []
    assert "只能" in capsys.readouterr().out


def test_cmd_fix_all_runs_dns_then_tcp_then_power(fake_run) -> None:
    run = _fix_runner(fake_run)
    assert fix.cmd_fix("all", run=run) is True

    mods = _mod_calls(run)
    assert mods == [
        [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            "name=以太网",
            "static",
            "223.5.5.5",
            "primary",
        ],
        [
            "netsh",
            "interface",
            "ipv4",
            "add",
            "dnsservers",
            "name=以太网",
            "119.29.29.29",
            "index=2",
        ],
    ]
    tcp_calls = [call for call in run.calls if call[:4] == ["netsh", "int", "tcp", "set"]]
    assert tcp_calls == _TCP_RULES
    power_calls = [call for call in run.calls if call[0] in ("powercfg", "reg")]
    assert power_calls == _POWER_RULES
    # 顺序：DNS 修改 → TCP → 电源
    assert run.calls.index(mods[0]) < run.calls.index(tcp_calls[0])
    assert run.calls.index(tcp_calls[0]) < run.calls.index(power_calls[0])


# ===========================================================================
# D9：失败提示不再把超时说成「系统不支持」
# ===========================================================================
def test_fix_tcp_reports_timeout_as_timeout(fake_run, capsys) -> None:
    timed_out = CmdResult(argv=["netsh"], code=-1, out="命令执行超时", timed_out=True)
    run = fake_run({("netsh",): timed_out})

    assert fix.fix_tcp(run=run) is False
    assert run.calls == _TCP_RULES  # 4 条规则参数不变
    out = capsys.readouterr().out
    assert "超时" in out
    assert "系统不支持" not in out


def test_fix_tcp_reports_missing_command_as_unsupported(fake_run, capsys) -> None:
    missing = CmdResult(argv=["netsh"], code=-1, out="找不到命令：netsh", missing=True)
    run = fake_run({("netsh",): missing})

    assert fix.fix_tcp(run=run) is False
    out = capsys.readouterr().out
    assert "系统不支持" in out
    assert "超时" not in out


def test_fix_power_argv_unchanged(fake_run) -> None:
    run = fake_run({}, default=("", 0))
    assert fix.fix_power(run=run) is True
    assert run.calls == _POWER_RULES


# ===========================================================================
# D5：cmp_tag
# ===========================================================================
def test_cmp_tag_improvement_is_not_reported_as_stable() -> None:
    """回归：旧实现 ``delta <= 1`` 吞掉负数，40→20 / 40→10 全被显示成「(稳定)」。"""
    line = fix.cmp_tag("DNS 解析", 40.0, 20.0)
    assert "↓20" in line
    assert "稳定" not in line

    line = fix.cmp_tag("DNS 解析", 40.0, 10.0)
    assert "↓30" in line
    assert "稳定" not in line


def test_cmp_tag_regression_and_stability_bands() -> None:
    assert "稳定" in fix.cmp_tag("延迟", 40.0, 41.0)
    assert "稳定" in fix.cmp_tag("延迟", 40.0, 39.0)
    assert "↑20" in fix.cmp_tag("延迟", 40.0, 60.0)
    assert "-" in fix.cmp_tag("延迟", None, 10.0)
    assert "-" in fix.cmp_tag("延迟", 40.0, None)


# ===========================================================================
# cmd_auto：三步流程 + 提权 + 复测用 cmp_tag
# ===========================================================================
def test_cmd_auto_non_admin_elevates_and_stops(fake_run, monkeypatch) -> None:
    elevated: list[list[str]] = []
    monkeypatch.setattr(platform_mod, "is_admin", lambda: False)
    monkeypatch.setattr(
        platform_mod, "elevate", lambda args, **kwargs: elevated.append(list(args)) or True
    )
    monkeypatch.setattr(probes, "dns_query", lambda *a, **k: 20.0)
    run = _fix_runner(fake_run)

    assert fix.cmd_auto(run=run) is False
    assert elevated == [["auto", "--wait"]]
    # 诊断跑过，但一条修改命令都不该发
    assert _mod_calls(run) == []
    assert all(call[0] not in ("powercfg", "reg") for call in run.calls)


def test_cmd_auto_retest_uses_cmp_tag_with_abs(fake_run, monkeypatch, capsys) -> None:
    monkeypatch.setattr(platform_mod, "is_admin", lambda: True)
    dns_values = iter([40.0, 10.0])
    monkeypatch.setattr(probes, "dns_query", lambda *a, **k: next(dns_values))
    run = _fix_runner(fake_run)

    assert fix.cmd_auto(run=run) is True
    out = capsys.readouterr().out
    assert "一键优化" in out
    assert "DNS 解析" in out
    assert "↓30" in out  # D5：改善必须显示为 ↓
    assert _mod_calls(run) == [
        [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            "name=以太网",
            "static",
            "223.5.5.5",
            "primary",
        ],
        [
            "netsh",
            "interface",
            "ipv4",
            "add",
            "dnsservers",
            "name=以太网",
            "119.29.29.29",
            "index=2",
        ],
    ]
