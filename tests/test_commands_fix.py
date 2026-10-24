# -*- coding: utf-8 -*-
"""``netopt.commands.fix`` 测试：计划 → journal intent → 执行。

**安全底线**：所有命令都经由注入的假 runner 执行；``conftest`` 的 autouse
夹具会拦住任何漏注入的真实调用。本文件不涉及真实 ``netsh`` / ``powercfg`` /
``reg`` / ``ipconfig``，也不读写真实状态目录（journal 一律用 ``tmp_path``）。

断言里的 argv 全部是**独立写出的字面量**，不从被模块取值 —— 实现改了参数，
测试才会跟着失败。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netopt import platform as platform_mod
from netopt.commands import fix as fix_mod
from netopt.commands.fix import FixKind, FixPlan, FixResult, apply_fix, plan_fix
from netopt.domain import FindingCode, Severity
from netopt.domain.changes import ChangeStatus
from netopt.domain.models import Adapter, InterfaceDns, Route
from netopt.platform import CmdResult
from netopt.system import FakeSystemApi
from netopt.system.journal import Journal, JournalError

INDEX = 7
NAME = "以太网"
VPN_NAME = "Radmin VPN"

WIRELESS = "2a737441-1930-4402-8d77-b2bebba308a3"
POWER = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
USB_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\USB"

TARGET = ["223.5.5.5", "119.29.29.29"]

DNS_SET = [
    "netsh",
    "interface",
    "ipv4",
    "set",
    "dnsservers",
    f"name={NAME}",
    "static",
    "223.5.5.5",
    "primary",
]
DNS_UNDO_SET = [
    "netsh",
    "interface",
    "ipv4",
    "set",
    "dnsservers",
    f"name={NAME}",
    "static",
    "192.0.2.1",
    "primary",
]
DNS_ADD = [
    "netsh",
    "interface",
    "ipv4",
    "add",
    "dnsservers",
    f"name={NAME}",
    "119.29.29.29",
    "index=2",
]
TCP_RULES = [
    ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
    ["netsh", "int", "tcp", "set", "global", "ecncapability=disabled"],
    ["netsh", "int", "tcp", "set", "global", "rss=enabled"],
    ["netsh", "int", "tcp", "set", "global", "nonsackrttresiliency=disabled"],
]
POWER_RULES = [
    ["powercfg", "/setacvalueindex", "SCHEME_CURRENT", WIRELESS, POWER, "0"],
    ["powercfg", "/setdcvalueindex", "SCHEME_CURRENT", WIRELESS, POWER, "0"],
    ["powercfg", "/setactive", "SCHEME_CURRENT"],
]
USB_ADD = [
    "reg",
    "add",
    USB_KEY,
    "/v",
    "DisableSelectiveSuspend",
    "/t",
    "REG_DWORD",
    "/d",
    "1",
    "/f",
]


# ---------------------------------------------------------------------------
# 测试数据
# ---------------------------------------------------------------------------
def _adapter(
    index: int = INDEX,
    name: str = NAME,
    *,
    is_primary: bool = True,
    connected: bool = True,
    kind: str = "ethernet",
) -> Adapter:
    """造一块最小适配器。"""
    return Adapter(
        index=index,
        guid=f"{{{index:08X}-0000-0000-0000-000000000000}}",
        name=name,
        description=name,
        mac=None,
        mtu=1500,
        connected=connected,
        kind=kind,
        is_primary=is_primary,
    )


def _route(index: int = INDEX, metric: int = 25) -> Route:
    """造一条 IPv4 默认路由。"""
    return Route(
        destination="0.0.0.0",
        prefix_len=0,
        next_hop="192.0.2.1",
        interface_index=index,
        metric=metric,
        is_default=True,
    )


def _dns(
    index: int = INDEX,
    name: str = NAME,
    *,
    servers: list[str] | None = None,
    source: str = "static",
) -> InterfaceDns:
    """造一份接口 DNS 配置。"""
    return InterfaceDns(
        adapter_index=index,
        interface_name=name,
        servers=["192.0.2.1"] if servers is None else servers,
        source=source,
    )


def _api(
    *,
    name: str = NAME,
    index: int = INDEX,
    is_primary: bool = True,
    kind: str = "ethernet",
    servers: list[str] | None = None,
    source: str = "static",
) -> FakeSystemApi:
    """默认路由落在给定适配器上的假系统。"""
    return FakeSystemApi(
        adapters=[_adapter(index, name, is_primary=is_primary, kind=kind)],
        routes=[_route(index)],
        dns_servers=[_dns(index, name, servers=servers, source=source)],
    )


_QUERY_TABLE: dict[tuple[str, ...], tuple[str, int]] = {
    ("netsh", "int", "tcp", "show", "global"): ("TCP 全局参数\n自动调优: normal", 0),
    ("powercfg", "/getactivescheme"): ("电源方案 GUID: 00000000", 0),
    ("powercfg", "/query"): ("当前交流电源设置索引: 0x00000000", 0),
    ("reg", "query"): ("DisableSelectiveSuspend REG_DWORD 0x1", 0),
}


def _query_run(fake_run, extra: dict[tuple[str, ...], object] | None = None):
    """带 TCP / 电源只读查询返回值的假 runner。"""
    table: dict[tuple[str, ...], object] = dict(_QUERY_TABLE)
    if extra:
        table.update(extra)
    return fake_run(table, default=("", 0))


# ---------------------------------------------------------------------------
# DNS：计划
# ---------------------------------------------------------------------------
def test_plan_dns_primary_interface_has_one_step() -> None:
    plan = plan_fix(FixKind.dns, api=_api())

    assert isinstance(plan, FixPlan)
    assert plan.blocked_reason is None
    assert len(plan.steps) == 1
    step = plan.steps[0]
    assert step.kind == "dns"
    assert step.target == NAME
    assert step.before == {"servers": ["192.0.2.1"], "source": "static"}
    assert step.after == {"servers": TARGET, "source": "static"}
    assert step.undo[0] == DNS_UNDO_SET


def test_plan_dns_non_primary_is_blocked() -> None:
    plan = plan_fix(FixKind.dns, api=_api(name=VPN_NAME, is_primary=False, kind="vpn"))

    assert plan.steps == []
    assert plan.blocked_reason == "未找到可配置 DNS 的主接口"
    assert any(finding.code == FindingCode.SYSTEM_UNAVAILABLE for finding in plan.findings)


def test_dns_undo_restores_all_static_servers() -> None:
    api = _api(servers=["192.0.2.1", "8.8.8.8"], source="static")

    undo = plan_fix(FixKind.dns, api=api).steps[0].undo

    assert undo[0] == DNS_UNDO_SET
    assert undo[1] == [
        "netsh",
        "interface",
        "ipv4",
        "add",
        "dnsservers",
        f"name={NAME}",
        "8.8.8.8",
        "index=2",
    ]


def test_dns_undo_uses_dhcp_when_source_is_dhcp() -> None:
    api = _api(servers=["192.0.2.1"], source="dhcp")

    undo = plan_fix(FixKind.dns, api=api).steps[0].undo

    assert undo == [
        ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={NAME}", "source=dhcp"]
    ]


# ---------------------------------------------------------------------------
# DNS：执行
# ---------------------------------------------------------------------------
def test_blocked_dns_performs_zero_writes(fake_run, tmp_path: Path) -> None:
    api = _api(name=VPN_NAME, is_primary=False, kind="vpn")
    run = fake_run({}, default=("", 0))
    journal_path = tmp_path / "changes.jsonl"

    result = apply_fix(FixKind.dns, api=api, run=run, journal=Journal(journal_path))

    assert run.calls == []
    assert result.applied == []
    assert result.failed == []
    assert not journal_path.exists()


def test_apply_dns_flushes_then_sets_static_in_order(fake_run, tmp_path: Path) -> None:
    run = fake_run({}, default=("", 0))
    journal = Journal(tmp_path / "changes.jsonl")

    result = apply_fix(FixKind.dns, api=_api(), run=run, journal=journal)

    assert run.calls == [["ipconfig", "/flushdns"], DNS_SET, DNS_ADD]
    assert len(result.applied) == 1
    loaded = journal.load()
    assert len(loaded) == 1
    assert loaded[0].status is ChangeStatus.applied
    assert loaded[0].kind == "dns"
    assert loaded[0].target == NAME
    assert loaded[0].before == {"servers": ["192.0.2.1"], "source": "static"}
    assert loaded[0].undo[0] == DNS_UNDO_SET


def test_apply_dns_already_target_skips_without_journal(fake_run, tmp_path: Path) -> None:
    api = _api(servers=list(TARGET))
    run = fake_run({}, default=("", 0))
    journal_path = tmp_path / "changes.jsonl"

    result = apply_fix(FixKind.dns, api=api, run=run, journal=Journal(journal_path))

    assert result.skipped == [NAME]
    assert result.applied == []
    assert run.calls == []
    assert not journal_path.exists()
    assert any(finding.code == "FIX_SKIPPED" for finding in result.findings)


def test_apply_dns_failure_marks_journal_failed(fake_run, tmp_path: Path) -> None:
    denied = CmdResult(argv=[], code=5, out="拒绝访问")
    run = fake_run({("netsh", "interface", "ipv4", "add", "dnsservers"): denied}, default=("", 0))
    journal = Journal(tmp_path / "changes.jsonl")

    result = apply_fix(FixKind.dns, api=_api(), run=run, journal=journal)

    assert len(result.failed) == 1
    change_id, error = result.failed[0]
    assert change_id
    assert "拒绝访问" in error
    assert [change.status for change in journal.load()] == [ChangeStatus.failed]
    assert any(finding.severity is Severity.critical for finding in result.findings)


def test_apply_dns_writes_intent_before_execution(tmp_path: Path) -> None:
    journal_path = tmp_path / "changes.jsonl"
    statuses: list[str | None] = []

    def run(argv, timeout=30.0, **kwargs):
        argv = list(argv)
        status: str | None = None
        if journal_path.exists():
            lines = journal_path.read_text(encoding="utf-8").splitlines()
            if lines:
                status = json.loads(lines[-1])["status"]
        statuses.append(status)
        return CmdResult(argv=argv, code=0, out="")

    apply_fix(FixKind.dns, api=_api(), run=run, journal=Journal(journal_path))

    # flush 不是变更步骤，在 intent 之前执行；两条 DNS 命令执行时 intent 必须已落盘。
    assert statuses[0] is None
    assert statuses[1] == "intent"
    assert statuses[2] == "intent"


def test_journal_failure_stops_before_any_dns_write(tmp_path: Path) -> None:
    class _BrokenJournal(Journal):
        def begin(self, *, kind, target, before, after, undo):  # type: ignore[override]
            raise JournalError("磁盘只读")

    calls: list[list[str]] = []

    def run(argv, timeout=30.0, **kwargs):
        argv = list(argv)
        calls.append(argv)
        return CmdResult(argv=argv, code=0, out="")

    result = apply_fix(
        FixKind.dns,
        api=_api(),
        run=run,
        journal=_BrokenJournal(tmp_path / "changes.jsonl"),
    )

    assert calls == [["ipconfig", "/flushdns"]]
    assert result.applied == []
    assert result.failed and result.failed[0][0] == ""
    assert "变更日志写入失败" in result.failed[0][1]


# ---------------------------------------------------------------------------
# dry-run：零副作用
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("kind", [FixKind.dns, FixKind.tcp, FixKind.power, FixKind.all])
def test_dry_run_has_zero_side_effects(kind: FixKind, fake_run, tmp_path: Path) -> None:
    run = fake_run({}, default=("", 0))
    journal_path = tmp_path / "changes.jsonl"

    result = apply_fix(
        kind,
        api=_api(),
        run=run,
        journal=Journal(journal_path),
        dry_run=True,
    )

    assert isinstance(result, FixResult)
    assert result.dry_run is True
    assert result.applied == []
    assert run.calls == []
    assert not journal_path.exists()
    assert any(finding.code == "FIX_DRY_RUN" for finding in result.findings)


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------
def test_plan_tcp_records_raw_before_and_empty_undo(fake_run) -> None:
    run = _query_run(fake_run)

    plan = plan_fix(FixKind.tcp, run=run)

    assert plan.blocked_reason is None
    assert len(plan.steps) == 1
    step = plan.steps[0]
    assert step.kind == "tcp"
    assert step.before == {"raw": "TCP 全局参数\n自动调优: normal"}
    assert step.after["rules"] == TCP_RULES
    # 原值解析未实现：不提供假的可回滚命令。
    assert step.undo == []
    assert any(
        finding.code == "FIX_ROLLBACK_MANUAL" and finding.severity is Severity.warn
        for finding in plan.findings
    )


def test_apply_tcp_runs_four_rules_in_order(fake_run, tmp_path: Path) -> None:
    run = _query_run(fake_run)
    journal = Journal(tmp_path / "changes.jsonl")

    result = apply_fix(FixKind.tcp, run=run, journal=journal)

    writes = [call for call in run.calls if call[:4] == ["netsh", "int", "tcp", "set"]]
    assert writes == TCP_RULES
    assert len(result.applied) == 1
    assert [change.status for change in journal.load()] == [ChangeStatus.applied]
    assert any(finding.code == "FIX_ROLLBACK_MANUAL" for finding in result.findings)


def test_tcp_query_failure_is_reported_but_plan_continues(fake_run) -> None:
    failed = CmdResult(argv=[], code=1, out="拒绝访问")
    run = fake_run({("netsh", "int", "tcp", "show", "global"): failed}, default=("", 0))

    plan = plan_fix(FixKind.tcp, run=run)

    assert len(plan.steps) == 1
    assert plan.steps[0].before == {"raw": "拒绝访问"}
    assert any(finding.code == "FIX_QUERY_FAILED" for finding in plan.findings)


# ---------------------------------------------------------------------------
# 电源 / 注册表
# ---------------------------------------------------------------------------
def test_plan_power_has_power_and_registry_steps(fake_run) -> None:
    run = _query_run(fake_run)

    plan = plan_fix(FixKind.power, run=run)

    assert plan.blocked_reason is None
    assert [step.kind for step in plan.steps] == ["power", "registry"]
    power, usb = plan.steps
    assert power.after["rules"] == POWER_RULES
    assert power.undo == [
        ["powercfg", "/setacvalueindex", "SCHEME_CURRENT", WIRELESS, POWER, "1"],
        ["powercfg", "/setdcvalueindex", "SCHEME_CURRENT", WIRELESS, POWER, "1"],
    ]
    assert power.before["raw"]["当前电源方案"] == "电源方案 GUID: 00000000"
    assert usb.before == {"raw": "DisableSelectiveSuspend REG_DWORD 0x1"}
    assert usb.after == {"DisableSelectiveSuspend": 1}
    assert usb.undo == [
        ["reg", "add", USB_KEY, "/v", "DisableSelectiveSuspend", "/t", "REG_DWORD", "/d", "0", "/f"]
    ]


def test_apply_power_runs_three_rules_then_usb(fake_run, tmp_path: Path) -> None:
    run = _query_run(fake_run)
    journal = Journal(tmp_path / "changes.jsonl")

    result = apply_fix(FixKind.power, run=run, journal=journal)

    assert run.calls[-4:] == [*POWER_RULES, USB_ADD]
    assert len(result.applied) == 2
    statuses = [change.status for change in journal.load()]
    assert statuses == [ChangeStatus.applied, ChangeStatus.applied]
    assert [change.kind for change in journal.load()] == ["power", "registry"]


# ---------------------------------------------------------------------------
# all 组合与依赖注入
# ---------------------------------------------------------------------------
def test_plan_all_combines_dns_tcp_power_steps(fake_run) -> None:
    run = _query_run(fake_run)

    plan = plan_fix(FixKind.all, api=_api(), run=run)

    assert plan.blocked_reason is None
    assert [step.kind for step in plan.steps] == ["dns", "tcp", "power", "registry"]


def test_plan_all_continues_when_dns_is_blocked(fake_run) -> None:
    run = _query_run(fake_run)
    api = _api(name=VPN_NAME, is_primary=False, kind="vpn")

    plan = plan_fix(FixKind.all, api=api, run=run)

    assert plan.blocked_reason is None
    assert [step.kind for step in plan.steps] == ["tcp", "power", "registry"]
    assert any(finding.code == FindingCode.SYSTEM_UNAVAILABLE for finding in plan.findings)


def test_default_api_is_built_at_call_time(monkeypatch) -> None:
    api = _api()
    monkeypatch.setattr(fix_mod, "LiveSystemApi", lambda: api)

    plan = plan_fix(FixKind.dns)

    assert len(plan.steps) == 1
    assert plan.steps[0].target == NAME


def test_default_runner_resolves_platform_run_at_call_time(monkeypatch) -> None:
    calls: list[list[str]] = []

    def _fake(argv, timeout=30.0, **kwargs):
        calls.append(list(argv))
        return CmdResult(argv=list(argv), code=0, out="")

    # conftest 已把 platform.run 换成陷阱函数；这里再换成记录器。
    monkeypatch.setattr(platform_mod, "run", _fake)

    plan_fix(FixKind.tcp)

    assert calls == [["netsh", "int", "tcp", "show", "global"]]
