# -*- coding: utf-8 -*-
"""修复命令（v2）—— 计划 → journal intent → 执行 → 结果。

与 v1 :mod:`netopt.fix` 的分工（``docs/SPEC.md`` §11、``docs/TASKS.md`` T4.2–T4.6）：

- **只改主接口**：DNS 的目标一律由 :func:`netopt.probes.primary_adapters_from_api`
  决定；拿不到主接口时直接 ``blocked``，**不执行任何写操作**（T4.6）。
- **先落盘再动手**：每个修复步骤先 ``journal.begin`` 写 intent 并 fsync，成功返回
  后才执行；执行结果再写 ``complete`` / ``fail``。日志写不进去就绝不继续。
- **写命令只走** :mod:`netopt.system.commands`：本模块不拼执行用的 argv，也不
  自己调 ``subprocess``。
- **支持 dry-run**：``apply_fix(..., dry_run=True)`` 只返回计划，不查询原值、
  不写 journal、不执行任何命令（含只读查询），保证零副作用。
- **不打印**：结果全部通过 :class:`FixResult` 返回，由 CLI / GUI 决定怎么展示。

已知限制（不要假称可自动回滚）：

- **TCP**：``query_tcp_settings`` 只回显给人看的对齐文本，**原值解析未实现**。
  因此 TCP 步骤的 ``undo`` 为空列表，``FixResult.findings`` 会明确提示
  「undo 需要人工确认」。
- **电源**：``query_power_settings`` 同样只保存原始文本；但 ``fix power`` 的目标
  是固定默认值（交流/直流索引 1、``DisableSelectiveSuspend=0``），因此可以给出
  确定的 undo 命令，不必解析原值。

Finding 码说明：:class:`netopt.domain.codes.FindingCode` 尚未定义修复相关的码，
本模块用 ``FIX_`` 前缀的模块级常量；阻塞场景仍使用既有的
``SYSTEM_UNAVAILABLE`` / ``PERMISSION_DENIED``。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from netopt import paths, platform, probes
from netopt.domain import Finding, FindingCode, Severity
from netopt.domain.models import Adapter, InterfaceDns
from netopt.platform import CmdResult, Runner
from netopt.system import LiveSystemApi, SystemApi
from netopt.system import commands as syscmd
from netopt.system.journal import Journal, JournalError

__all__ = [
    "PRIMARY_DNS",
    "SECONDARY_DNS",
    "FixKind",
    "FixPlan",
    "FixResult",
    "FixStep",
    "apply_fix",
    "plan_fix",
]

#: 目标 DNS（与 v1 一致，阿里 / 腾讯公共 DNS）。
PRIMARY_DNS = "223.5.5.5"
SECONDARY_DNS = "119.29.29.29"
TARGET_DNS = [PRIMARY_DNS, SECONDARY_DNS]

#: 无线网卡节能与 USB 选择性暂停的相关常量。
#: 这里只用于**记录** undo 命令，真正执行仍走 :mod:`netopt.system.commands`。
_WIRELESS_GUID = "2a737441-1930-4402-8d77-b2bebba308a3"
_POWER_GUID = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
_USB_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\USB"

#: 找不到主接口时的固定原因（CLI 直接展示这句话）。
_NO_PRIMARY_REASON = "未找到可配置 DNS 的主接口"
#: 读不到当前 DNS 时的阻塞原因。
_NO_DNS_REASON = "无法读取当前 DNS 配置"

# 修复层 Finding 码（FindingCode 尚无对应成员，见模块 docstring）。
_FIX_APPLIED = "FIX_APPLIED"
_FIX_FAILED = "FIX_FAILED"
_FIX_SKIPPED = "FIX_SKIPPED"
_FIX_DRY_RUN = "FIX_DRY_RUN"
_FIX_BLOCKED = "FIX_BLOCKED"
_FIX_ROLLBACK_MANUAL = "FIX_ROLLBACK_MANUAL"
_FIX_QUERY_FAILED = "FIX_QUERY_FAILED"


class FixKind(StrEnum):
    """可执行的修复类别。"""

    dns = "dns"
    tcp = "tcp"
    power = "power"
    all = "all"


@dataclass(frozen=True)
class FixStep:
    """计划中的一步修复。

    ``before`` / ``after`` 是写进 journal 的结构化快照；``undo`` 是可直接执行的
    argv 列表，由 ``netopt undo`` 消费，本模块只记录不执行。``kind`` 取
    ``dns | tcp | power | registry``。
    """

    description: str
    kind: str
    target: str
    before: dict[str, Any]
    after: dict[str, Any]
    undo: list[list[str]]


@dataclass(frozen=True)
class FixPlan:
    """一次修复的完整计划。

    ``blocked_reason`` 非 ``None`` 时表示**计划阶段就无法安全执行**（例如找不到
    主接口）：调用方必须不执行任何写操作。
    """

    steps: list[FixStep]
    findings: list[Finding]
    blocked_reason: str | None = None


@dataclass(frozen=True)
class FixResult:
    """一次修复的执行结果。

    ``applied`` 是成功写入并标记为 ``applied`` 的 change id；``failed`` 是
    ``(change id, 错误说明)``；``skipped`` 是无需修改的步骤标识（DNS 为接口名）。
    """

    kind: FixKind
    applied: list[str]
    failed: list[tuple[str, str]]
    skipped: list[str]
    findings: list[Finding]
    dry_run: bool = False


# ---------------------------------------------------------------------------
# 依赖解析与 Finding 构造
# ---------------------------------------------------------------------------
def _resolve_api(api: SystemApi | None) -> SystemApi:
    """在**调用时**解析 ``api``：默认构造 :class:`LiveSystemApi`。"""
    return api if api is not None else LiveSystemApi()


def _resolve_run(run: Runner | None) -> Runner:
    """在**调用时**解析 ``run``：默认取 :func:`netopt.platform.run`。"""
    return run if run is not None else platform.run


def _finding(
    code: str,
    severity: Severity,
    title: str,
    detail: str,
    *,
    advice: list[str] | None = None,
) -> Finding:
    """构造一条修复层 Finding。"""
    return Finding(
        code=code,
        severity=severity,
        title=title,
        detail=detail,
        advice=[] if advice is None else advice,
    )


def _blocked_finding(reason: str, detail: str) -> Finding:
    """计划无法执行时的 Finding（沿用既有的 ``SYSTEM_UNAVAILABLE`` 码）。"""
    return _finding(
        FindingCode.SYSTEM_UNAVAILABLE,
        Severity.warn,
        reason,
        detail,
        advice=["确认默认路由承载在物理网卡上，并以管理员身份重试"],
    )


def _read_failure_finding(what: str, exc: BaseException) -> Finding:
    """读取系统状态失败（API 抛异常）时的 Finding。"""
    return _finding(
        FindingCode.SYSTEM_UNAVAILABLE,
        Severity.warn,
        f"无法读取{what}",
        f"{type(exc).__name__}: {exc}"[:300],
        advice=["确认系统 API 可用并以管理员身份重试"],
    )


# ---------------------------------------------------------------------------
# DNS 计划
# ---------------------------------------------------------------------------
def _dns_before(record: InterfaceDns | None) -> dict[str, Any]:
    """把接口当前的 :class:`InterfaceDns` 转成 journal 的 ``before``。"""
    if record is None:
        return {"servers": [], "source": "none", "note": "未读取到原值"}
    return {"servers": list(record.servers), "source": record.source}


def _dns_undo(interface: str, record: InterfaceDns | None) -> list[list[str]]:
    """按原 DNS 来源生成还原命令（只记录，不执行）。

    - ``source=static`` 且有地址：第一条 ``set ... static <ip> primary``，
      其余依次 ``add ... index=n``（n 从 2 开始）；
    - ``dhcp`` / ``none``（含读取失败）：``set ... source=dhcp``。
    """
    if record is not None and record.source == "static" and record.servers:
        servers = list(record.servers)
        undo = [
            [
                "netsh",
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                f"name={interface}",
                "static",
                servers[0],
                "primary",
            ]
        ]
        undo.extend(
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "dnsservers",
                f"name={interface}",
                server,
                f"index={index}",
            ]
            for index, server in enumerate(servers[1:], start=2)
        )
        return undo
    return [["netsh", "interface", "ipv4", "set", "dnsservers", f"name={interface}", "source=dhcp"]]


def _dns_record_for(adapter: Adapter, records: dict[int, InterfaceDns]) -> InterfaceDns | None:
    """按适配器 index 取 DNS 记录；index 对不上时退回按接口名匹配。"""
    record = records.get(adapter.index)
    if record is not None:
        return record
    return next((item for item in records.values() if item.interface_name == adapter.name), None)


def _plan_dns(api: SystemApi) -> FixPlan:
    """生成 DNS 修复计划。

    目标接口只取 :func:`netopt.probes.primary_adapters_from_api` 的结果。该函数
    为空时返回 ``blocked``，**不会执行任何写操作**（缺陷 D11 / T4.6）。
    """
    try:
        adapters = probes.primary_adapters_from_api(api)
    except Exception as exc:  # 探测边界：读不到接口也要变成可解释的数据
        return FixPlan(
            steps=[],
            findings=[_read_failure_finding("主接口", exc)],
            blocked_reason=_NO_PRIMARY_REASON,
        )
    if not adapters:
        return FixPlan(
            steps=[],
            findings=[
                _blocked_finding(
                    _NO_PRIMARY_REASON,
                    "默认路由不在可配置 DNS 的物理/主接口上（可能落在 VPN、"
                    "虚拟交换机或未连接网卡）。为避免打断内网解析，未执行任何修改。",
                )
            ],
            blocked_reason=_NO_PRIMARY_REASON,
        )

    try:
        records = {item.adapter_index: item for item in api.dns_servers()}
    except Exception as exc:
        return FixPlan(
            steps=[],
            findings=[_read_failure_finding(" DNS 配置", exc)],
            blocked_reason=_NO_DNS_REASON,
        )

    steps: list[FixStep] = []
    findings: list[Finding] = []
    for adapter in adapters:
        record = _dns_record_for(adapter, records)
        before = _dns_before(record)
        undo = _dns_undo(adapter.name, record)
        if record is None:
            findings.append(
                _finding(
                    _FIX_QUERY_FAILED,
                    Severity.info,
                    f"未读取到接口 [{adapter.name}] 的 DNS 原值",
                    "无法确定原值，undo 将按 DHCP 处理；如需精确回滚请先手工确认。",
                    advice=["运行 'netsh interface ipv4 show dnsservers' 查看当前配置"],
                )
            )
        steps.append(
            FixStep(
                description=(f"接口 [{adapter.name}] 设置 DNS: {PRIMARY_DNS} / {SECONDARY_DNS}"),
                kind="dns",
                target=adapter.name,
                before=before,
                after={"servers": list(TARGET_DNS), "source": "static"},
                undo=undo,
            )
        )
    return FixPlan(steps=steps, findings=findings, blocked_reason=None)


# ---------------------------------------------------------------------------
# TCP / 电源计划
# ---------------------------------------------------------------------------
def _tcp_rule_argv() -> list[list[str]]:
    """返回实际会执行的 TCP 规则 argv（测试可直接比对）。"""
    return [
        ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
        ["netsh", "int", "tcp", "set", "global", "ecncapability=disabled"],
        ["netsh", "int", "tcp", "set", "global", "rss=enabled"],
        ["netsh", "int", "tcp", "set", "global", "nonsackrttresiliency=disabled"],
    ]


def _query_raw(
    run: Runner,
    query: Callable[..., list[tuple[str, CmdResult]]],
    *,
    enabled: bool,
) -> tuple[dict[str, str], bool]:
    """执行一次只读查询并返回 ``({标签: 原始输出}, 是否全部成功)``。

    ``enabled=False``（dry-run）时**不执行任何命令**，返回空字典与 ``True``。
    """
    if not enabled:
        return {}, True
    entries = list(query(run=run))
    raw = {label: result.out for label, result in entries}
    ok = all(result.ok for _, result in entries)
    return raw, ok


def _plan_tcp(run: Runner, *, query: bool) -> FixPlan:
    """生成 TCP 修复计划。

    **原值解析未实现**：``netsh int tcp show global`` 的输出是给人看的对齐文本，
    本模块只把它原样塞进 ``before["raw"]``，无法安全地反推原始参数。因此
    ``undo`` 一律为空列表，并在 Finding 里要求人工确认——不要假称可自动回滚。
    """
    raw, ok = _query_raw(run, syscmd.query_tcp_settings, enabled=query)
    before: dict[str, Any]
    if query:
        before = {"raw": raw.get("TCP 全局参数", "")}
    else:
        before = {"raw": None, "note": "dry-run 未查询原值"}

    findings: list[Finding] = []
    if query and not ok:
        findings.append(
            _finding(
                _FIX_QUERY_FAILED,
                Severity.warn,
                "TCP 原值查询失败",
                "无法读取 'netsh int tcp show global'，执行记录里的 before 可能不完整。",
                advice=["以管理员身份重新运行，或先手工执行该命令确认当前值"],
            )
        )
    findings.append(
        _finding(
            _FIX_ROLLBACK_MANUAL,
            Severity.warn,
            "TCP 原值解析未实现，无法自动回滚",
            "TCP 修复的 before 只保存原始文本，undo 为空；回滚需要人工对照原值确认。",
            advice=["执行前先运行 'netsh int tcp show global' 并保存输出"],
        )
    )
    return FixPlan(
        steps=[
            FixStep(
                description="调整 TCP 全局参数（4 条规则）",
                kind="tcp",
                target="netsh int tcp set global",
                before=before,
                after={"rules": _tcp_rule_argv()},
                undo=[],
            )
        ],
        findings=findings,
        blocked_reason=None,
    )


def _power_rules() -> list[list[str]]:
    """三条电源规则（与 :func:`netopt.system.commands.set_power_settings` 一致）。"""
    return [
        ["powercfg", "/setacvalueindex", "SCHEME_CURRENT", _WIRELESS_GUID, _POWER_GUID, "0"],
        ["powercfg", "/setdcvalueindex", "SCHEME_CURRENT", _WIRELESS_GUID, _POWER_GUID, "0"],
        ["powercfg", "/setactive", "SCHEME_CURRENT"],
    ]


def _power_undo() -> list[list[str]]:
    """把无线网卡节能恢复为默认值（交流/直流索引 1）。"""
    return [
        ["powercfg", "/setacvalueindex", "SCHEME_CURRENT", _WIRELESS_GUID, _POWER_GUID, "1"],
        ["powercfg", "/setdcvalueindex", "SCHEME_CURRENT", _WIRELESS_GUID, _POWER_GUID, "1"],
    ]


def _usb_undo() -> list[list[str]]:
    """恢复 USB 选择性暂停（``DisableSelectiveSuspend=0`` 表示允许挂起）。"""
    return [
        [
            "reg",
            "add",
            _USB_KEY,
            "/v",
            "DisableSelectiveSuspend",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ]
    ]


def _plan_power(run: Runner, *, query: bool) -> FixPlan:
    """生成电源修复计划：三条 powercfg 规则 + 一条 USB 注册表规则。

    ``before`` 保存 ``query_power_settings`` 的原始文本；目标值是固定默认值，
    因此 undo 可以确定写出（交流/直流索引 1、注册表 ``0``）。
    """
    raw, ok = _query_raw(run, syscmd.query_power_settings, enabled=query)
    if query:
        power_before: dict[str, Any] = {
            "raw": {
                "当前电源方案": raw.get("当前电源方案", ""),
                "无线网卡节能 (交流/直流)": raw.get("无线网卡节能 (交流/直流)", ""),
            }
        }
        usb_before: dict[str, Any] = {"raw": raw.get("USB 选择性暂停", "")}
    else:
        note = "dry-run 未查询原值"
        power_before = {"raw": None, "note": note}
        usb_before = {"raw": None, "note": note}

    findings: list[Finding] = []
    if query and not ok:
        findings.append(
            _finding(
                _FIX_QUERY_FAILED,
                Severity.warn,
                "电源原值查询失败",
                "无法完整读取电源方案 / 注册表原值，执行记录里的 before 可能不完整。",
                advice=["以管理员身份重新运行，或先手工执行 powercfg / query 确认当前值"],
            )
        )

    return FixPlan(
        steps=[
            FixStep(
                description="禁用无线网卡节能（交流/直流）",
                kind="power",
                target="powercfg",
                before=power_before,
                after={"rules": _power_rules()},
                undo=_power_undo(),
            ),
            FixStep(
                description="禁用 USB 选择性暂停",
                kind="registry",
                target=_USB_KEY,
                before=usb_before,
                after={"DisableSelectiveSuspend": 1},
                undo=_usb_undo(),
            ),
        ],
        findings=findings,
        blocked_reason=None,
    )


# ---------------------------------------------------------------------------
# 计划入口
# ---------------------------------------------------------------------------
def _build_plan(kind: FixKind, *, api: SystemApi, run: Runner, query: bool) -> FixPlan:
    """按修复类别组合计划。

    ``query=False`` 只供 ``apply_fix(dry_run=True)`` 使用：不执行任何只读查询，
    保证 dry-run 零副作用。
    """
    if kind == FixKind.dns:
        return _plan_dns(api)
    if kind == FixKind.tcp:
        return _plan_tcp(run, query=query)
    if kind == FixKind.power:
        return _plan_power(run, query=query)

    dns_plan = _plan_dns(api)
    tcp_plan = _plan_tcp(run, query=query)
    power_plan = _plan_power(run, query=query)
    steps = [*dns_plan.steps, *tcp_plan.steps, *power_plan.steps]
    findings = [*dns_plan.findings, *tcp_plan.findings, *power_plan.findings]
    # DNS 被阻塞不应连累 TCP/电源（它们不依赖默认路由接口）。
    blocked = dns_plan.blocked_reason if not steps else None
    return FixPlan(steps=steps, findings=findings, blocked_reason=blocked)


def plan_fix(
    kind: FixKind,
    *,
    api: SystemApi | None = None,
    run: Runner | None = None,
) -> FixPlan:
    """生成修复计划，**不执行任何写操作**。

    只读查询（TCP / 电源原值）会执行，用于填充 journal 的 ``before``；
    DNS 只通过 :class:`SystemApi` 读接口状态，不跑子进程。
    """
    return _build_plan(
        kind,
        api=_resolve_api(api),
        run=_resolve_run(run),
        query=True,
    )


# ---------------------------------------------------------------------------
# 执行
# ---------------------------------------------------------------------------
def _dns_is_noop(step: FixStep) -> bool:
    """DNS 步骤的当前值是否已经等于目标值（是则跳过，不写 journal）。"""
    if step.kind != "dns":
        return False
    before = step.before.get("servers")
    after = step.after.get("servers")
    if not isinstance(before, list) or not isinstance(after, list):
        return False
    return {str(item) for item in before} == {str(item) for item in after}


def _one_line(text: str, limit: int = 80) -> str:
    """把命令输出压成一行，最多 ``limit`` 个字符。"""
    compact = " ".join(text.split())
    return compact[:limit]


def _result_error(label: str, result: CmdResult) -> str:
    """把一条失败命令翻译成可读原因。"""
    if result.timed_out:
        reason = "命令执行超时"
    elif result.missing:
        reason = "系统不支持该命令"
    else:
        reason = f"退出码 {result.code}"
        text = _one_line(result.out)
        if text:
            reason = f"{reason}: {text}"
    return f"{label} → {reason}"


def _first_error(entries: list[tuple[str, CmdResult]]) -> str | None:
    """返回所有失败命令的说明；全部成功返回 ``None``。"""
    errors = [_result_error(label, result) for label, result in entries if not result.ok]
    return "；".join(errors) if errors else None


def _execute_step(step: FixStep, run: Runner) -> list[tuple[str, CmdResult]]:
    """执行一个修复步骤，返回 ``[(说明, 结果), ...]``。

    所有写命令都经 :mod:`netopt.system.commands`；本函数不拼执行用 argv。
    """
    if step.kind == "dns":
        results = syscmd.set_dns_static(step.target, list(TARGET_DNS), run=run)
        return [
            (f"接口 [{step.target}] {server}", result)
            for server, result in zip(TARGET_DNS, results, strict=False)
        ]
    if step.kind == "tcp":
        return list(syscmd.set_tcp_settings(run=run))
    if step.kind == "power":
        return list(syscmd.set_power_settings(run=run))
    if step.kind == "registry":
        return [("禁用 USB 选择性暂停", syscmd.set_usb_selective_suspend(run=run))]
    raise ValueError(f"未知修复步骤类型: {step.kind}")


def _apply_blocked(plan: FixPlan, kind: FixKind) -> FixResult:
    """计划被阻塞：原样返回 Finding，不写 journal、不执行命令。"""
    findings = list(plan.findings)
    findings.append(
        _finding(
            _FIX_BLOCKED,
            Severity.info,
            "未执行任何修改",
            plan.blocked_reason or "计划阶段被阻塞",
        )
    )
    return FixResult(kind=kind, applied=[], failed=[], skipped=[], findings=findings)


def _summary_findings(
    applied: list[str],
    applied_descriptions: list[str],
    failed: list[tuple[str, str]],
    skipped: list[str],
) -> list[Finding]:
    """生成「成功 / 失败 / 跳过」摘要 Finding。"""
    findings: list[Finding] = []
    if applied:
        findings.append(
            _finding(
                _FIX_APPLIED,
                Severity.info,
                f"已应用 {len(applied)} 项修复",
                "；".join(applied_descriptions) if applied_descriptions else "变更已写入日志",
            )
        )
    if skipped:
        findings.append(
            _finding(
                _FIX_SKIPPED,
                Severity.info,
                f"跳过 {len(skipped)} 项（已是目标状态）",
                ", ".join(skipped),
            )
        )
    if failed:
        findings.append(
            _finding(
                _FIX_FAILED,
                Severity.critical,
                f"{len(failed)} 项修复失败",
                "；".join(error for _change_id, error in failed),
                advice=["检查管理员权限后重试", "按 journal 中的 undo 手工回滚"],
            )
        )
    if not applied and not failed and not skipped:
        findings.append(_finding(_FIX_APPLIED, Severity.info, "没有需要执行的修复", "计划为空"))
    return findings


def apply_fix(
    kind: FixKind,
    *,
    api: SystemApi | None = None,
    run: Runner | None = None,
    journal: Journal | None = None,
    dry_run: bool = False,
) -> FixResult:
    """按计划执行修复。

    - 每一步先 ``journal.begin``（fsync）再执行，成功后 ``complete``、失败后
      ``fail``；journal 写入失败时立刻停止，绝不继续执行；
    - ``dry_run=True`` 只生成计划并返回，**不执行任何命令（含只读查询）、
      不写 journal**；
    - DNS 已是目标值时记为 ``skipped``，不写 journal；
    - ``journal=None`` 时在调用时才构造 ``Journal(paths.journal_path())``。
    """
    resolved_api = _resolve_api(api)
    resolved_run = _resolve_run(run)
    plan = _build_plan(
        kind,
        api=resolved_api,
        run=resolved_run,
        query=not dry_run,
    )
    findings = list(plan.findings)

    if dry_run:
        findings.append(
            _finding(
                _FIX_DRY_RUN,
                Severity.info,
                "dry-run：未执行任何修改",
                f"计划共 {len(plan.steps)} 步；未查询原值、未写 journal、未执行命令。",
            )
        )
        skipped_steps = [step.target for step in plan.steps if _dns_is_noop(step)]
        return FixResult(
            kind=kind,
            applied=[],
            failed=[],
            skipped=skipped_steps,
            findings=findings,
            dry_run=True,
        )

    if plan.blocked_reason is not None:
        return _apply_blocked(plan, kind)

    book = journal if journal is not None else Journal(paths.journal_path())
    applied: list[str] = []
    applied_descriptions: list[str] = []
    failed: list[tuple[str, str]] = []
    skipped: list[str] = []

    # DNS 缓存只在确实要改 DNS 时清一次；全部跳过时不碰系统。
    if any(step.kind == "dns" and not _dns_is_noop(step) for step in plan.steps):
        flushed = syscmd.flush_dns(run=resolved_run)
        if not flushed.ok:
            findings.append(
                _finding(
                    _FIX_QUERY_FAILED,
                    Severity.warn,
                    "DNS 缓存清理失败",
                    _result_error("ipconfig /flushdns", flushed),
                    advice=["DNS 设置仍可继续；稍后可手工执行 ipconfig /flushdns"],
                )
            )

    for step in plan.steps:
        if _dns_is_noop(step):
            skipped.append(step.target)
            continue

        try:
            change = book.begin(
                kind=step.kind,
                target=step.target,
                before=step.before,
                after=step.after,
                undo=step.undo,
            )
        except JournalError as exc:
            failed.append(("", f"变更日志写入失败: {exc}"))
            findings.append(
                _finding(
                    _FIX_FAILED,
                    Severity.critical,
                    "变更日志写入失败，已停止后续修复",
                    str(exc),
                    advice=["检查状态目录权限后重试"],
                )
            )
            break

        try:
            entries = _execute_step(step, resolved_run)
        except Exception as exc:  # 执行边界：任何异常都要落成 failed，不能留下裸 intent
            entries = []
            error: str | None = f"{type(exc).__name__}: {exc}"
        else:
            error = _first_error(entries)

        if error is None:
            try:
                book.complete(change.id, result=f"已执行 {len(entries)} 条命令")
            except JournalError as exc:
                failed.append((change.id, f"执行成功但日志写入失败: {exc}"))
                findings.append(
                    _finding(
                        _FIX_FAILED,
                        Severity.critical,
                        "修复已执行，但结果未能写入日志",
                        f"{step.description}: {exc}",
                        advice=["检查状态目录；必要时手工核对系统状态"],
                    )
                )
                continue
            applied.append(change.id)
            applied_descriptions.append(step.description)
        else:
            try:
                book.fail(change.id, error=error)
            except JournalError as exc:
                findings.append(
                    _finding(
                        _FIX_FAILED,
                        Severity.critical,
                        "修复失败，且失败状态未能写入日志",
                        f"{step.description}: {error}；日志错误: {exc}",
                    )
                )
            failed.append((change.id, error))

    findings.extend(_summary_findings(applied, applied_descriptions, failed, skipped))
    return FixResult(
        kind=kind,
        applied=applied,
        failed=failed,
        skipped=skipped,
        findings=findings,
        dry_run=False,
    )
