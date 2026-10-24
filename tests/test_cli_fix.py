# -*- coding: utf-8 -*-
"""``netopt fix`` / ``netopt undo`` 的 CLI 与回滚层测试。

**安全底线**：本文件不执行任何真实系统命令。

- CLI 测试把 ``netopt.commands.fix.apply_fix`` / ``undo.undo_last`` /
  ``undo.undo`` 全部换成记录器；
- 回滚层测试使用 ``tmp_path`` 下的 journal 与注入的 fake runner；
- ``conftest`` 的 autouse 夹具仍会拦住任何漏注入的真实子进程。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import netopt.cli as cli
from netopt import platform
from netopt.commands import fix as fix_mod
from netopt.commands import undo as undo_mod
from netopt.commands.fix import FixKind, FixResult
from netopt.commands.undo import UndoResult, undo, undo_last
from netopt.domain import Finding, Severity
from netopt.domain.changes import ChangeStatus
from netopt.platform import CmdResult
from netopt.system.journal import Journal

runner = CliRunner()


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
def _fix_result(
    kind: FixKind,
    *,
    applied: list[str] | None = None,
    failed: list[tuple[str, str]] | None = None,
    skipped: list[str] | None = None,
    findings: list[Finding] | None = None,
    dry_run: bool = False,
) -> FixResult:
    """构造一个可控的 :class:`FixResult`。"""
    return FixResult(
        kind=kind,
        applied=[] if applied is None else applied,
        failed=[] if failed is None else failed,
        skipped=[] if skipped is None else skipped,
        findings=[] if findings is None else findings,
        dry_run=dry_run,
    )


def _install_apply(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: FixResult | None = None,
    error: Exception | None = None,
    admin: bool = True,
) -> list[tuple[FixKind, bool]]:
    """替换 ``fix.apply_fix`` 并记录 ``(kind, dry_run)``。"""
    monkeypatch.setattr(platform, "is_admin", lambda: admin)
    calls: list[tuple[FixKind, bool]] = []

    def fake_apply(kind: FixKind, *, dry_run: bool = False, **kwargs: object) -> FixResult:
        calls.append((kind, dry_run))
        if error is not None:
            raise error
        if result is not None:
            return result
        return _fix_result(kind, dry_run=dry_run)

    monkeypatch.setattr(fix_mod, "apply_fix", fake_apply)
    return calls


def _install_undo_last(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: UndoResult | None = None,
    error: Exception | None = None,
    admin: bool = True,
) -> list[str | None]:
    """替换 ``undo.undo_last`` 并记录 ``kind``。"""
    monkeypatch.setattr(platform, "is_admin", lambda: admin)
    calls: list[str | None] = []

    def fake_undo_last(*, kind: str | None = None, **kwargs: object) -> UndoResult:
        calls.append(kind)
        if error is not None:
            raise error
        return result if result is not None else UndoResult("id-1", 1, [], "已回滚 1 条命令")

    monkeypatch.setattr(undo_mod, "undo_last", fake_undo_last)
    return calls


def _journal_with(
    tmp_path: Path,
    *,
    undo_argv: list[list[str]],
    kind: str = "dns",
    applied: bool = True,
) -> tuple[Journal, str]:
    """在临时目录写一条变更记录，返回 ``(journal, change_id)``。"""
    journal = Journal(tmp_path / "changes.jsonl")
    change = journal.begin(
        kind=kind,
        target="以太网",
        before={"servers": ["192.0.2.1"]},
        after={"servers": ["223.5.5.5"]},
        undo=undo_argv,
    )
    if applied:
        journal.complete(change.id)
    return journal, change.id


def _fake_runner(
    codes: dict[tuple[str, ...], tuple[int, str]] | None = None,
) -> tuple[object, list[list[str]]]:
    """按 argv 前缀返回预设结果；返回 ``(runner, calls)``。"""
    table = {} if codes is None else codes
    calls: list[list[str]] = []

    def run(argv: list[str], timeout: float = 30.0, **kwargs: object) -> CmdResult:
        argv = [str(item) for item in argv]
        calls.append(argv)
        code, out = table.get(tuple(argv), (0, ""))
        return CmdResult(argv=argv, code=code, out=out)

    return run, calls


# ---------------------------------------------------------------------------
# fix：参数解析与 dry-run
# ---------------------------------------------------------------------------
def test_fix_defaults_to_all(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_apply(monkeypatch)

    result = runner.invoke(cli.app, ["fix"])

    assert result.exit_code == 0
    assert calls == [(FixKind.all, False)]


@pytest.mark.parametrize("kind", ["dns", "tcp", "power", "all"])
def test_fix_accepts_every_kind(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    calls = _install_apply(monkeypatch)

    result = runner.invoke(cli.app, ["fix", kind])

    assert result.exit_code == 0
    assert calls == [(FixKind(kind), False)]


def test_fix_invalid_kind_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_apply(monkeypatch)

    result = runner.invoke(cli.app, ["fix", "bogus"])

    assert result.exit_code == 1
    assert calls == [], "非法 kind 不得调用 apply_fix"
    assert "用法错误" in result.stderr


def test_fix_dry_run_passes_flag_and_skips_admin_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """dry-run 零副作用，因此非管理员也允许执行。"""
    calls = _install_apply(monkeypatch, admin=False)

    result = runner.invoke(cli.app, ["fix", "tcp", "--dry-run"])

    assert result.exit_code == 0
    assert calls == [(FixKind.tcp, True)]
    assert "dry-run" in result.stdout
    assert "未执行" in result.stdout


def test_fix_non_admin_exits_3_without_calling_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_apply(monkeypatch, admin=False)

    result = runner.invoke(cli.app, ["fix", "dns"])

    assert result.exit_code == 3
    assert calls == [], "非管理员绝不能执行修复"
    assert "以管理员身份运行" in result.stdout


def test_fix_invalid_kind_checked_before_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    """非法 kind 优先报用法错误（exit 1），而不是权限错误。"""
    _install_apply(monkeypatch, admin=False)

    result = runner.invoke(cli.app, ["fix", "bogus"])

    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# fix：退出码与 JSON
# ---------------------------------------------------------------------------
def test_fix_success_exits_0(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_apply(monkeypatch, result=_fix_result(FixKind.dns, applied=["id-1"]))

    result = runner.invoke(cli.app, ["fix", "dns"])

    assert result.exit_code == 0
    assert "已应用 id-1" in result.stdout


def test_fix_failure_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_apply(
        monkeypatch,
        result=_fix_result(FixKind.dns, failed=[("id-1", "netsh 退出码 1")]),
    )

    result = runner.invoke(cli.app, ["fix", "dns"])

    assert result.exit_code == 2
    assert "失败 id-1" in result.stdout


def test_fix_internal_error_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_apply(monkeypatch, error=RuntimeError("炸了"))

    result = runner.invoke(cli.app, ["--json", "fix", "dns"])

    assert result.exit_code == 4
    assert result.stdout == "", "内部错误不得污染 stdout"
    assert "内部错误" in result.stderr


def test_fix_json_stdout_is_only_json(monkeypatch: pytest.MonkeyPatch) -> None:
    finding = Finding(
        code="FIX_APPLIED",
        severity=Severity.info,
        title="已应用",
        detail="测试用固定结论",
    )
    _install_apply(
        monkeypatch,
        result=_fix_result(FixKind.dns, applied=["id-1"], findings=[finding]),
    )

    result = runner.invoke(cli.app, ["fix", "dns", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)  # 整段可解析 → 没有夹带提示行
    assert payload["kind"] == "dns"
    assert payload["applied"] == ["id-1"]
    assert payload["failed"] == []
    assert payload["findings"][0]["severity"] == "info"


def test_fix_json_permission_still_emits_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_apply(monkeypatch, admin=False)

    result = runner.invoke(cli.app, ["fix", "dns", "--json"])

    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["kind"] == "dns"
    assert payload["applied"] == []
    assert "以管理员身份运行" in payload["findings"][0]["detail"]


# ---------------------------------------------------------------------------
# fix --restore：映射到 undo_last(kind="dns")
# ---------------------------------------------------------------------------
def test_restore_maps_to_undo_last_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_undo_last(
        monkeypatch,
        result=UndoResult("id-1", 1, [], "已回滚 1 条命令"),
    )

    def boom_apply(*args: object, **kwargs: object) -> None:
        raise AssertionError("--restore 不应调用 apply_fix")

    monkeypatch.setattr(fix_mod, "apply_fix", boom_apply)

    result = runner.invoke(cli.app, ["fix", "dns", "--restore"])

    assert result.exit_code == 0
    assert calls == ["dns"]


def test_restore_failure_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_undo_last(
        monkeypatch,
        result=UndoResult("id-1", 0, [(["netsh"], "失败")], "回滚失败"),
    )

    result = runner.invoke(cli.app, ["fix", "dns", "--restore"])

    assert result.exit_code == 2


def test_restore_dry_run_does_not_execute(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_undo_last(monkeypatch)

    result = runner.invoke(cli.app, ["fix", "dns", "--restore", "--dry-run"])

    assert result.exit_code == 0
    assert calls == [], "dry-run 不得真的执行回滚"
    assert "dry-run" in result.stdout


# ---------------------------------------------------------------------------
# undo 命令
# ---------------------------------------------------------------------------
def test_undo_defaults_to_last(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_undo_last(monkeypatch)

    result = runner.invoke(cli.app, ["undo"])

    assert result.exit_code == 0
    assert calls == [None]


def test_undo_explicit_id_calls_undo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "is_admin", lambda: True)
    seen: list[str] = []

    def fake_undo(change_id: str, **kwargs: object) -> UndoResult:
        seen.append(change_id)
        return UndoResult(change_id, 1, [], "已回滚 1 条命令")

    monkeypatch.setattr(undo_mod, "undo", fake_undo)

    result = runner.invoke(cli.app, ["undo", "abc-123"])

    assert result.exit_code == 0
    assert seen == ["abc-123"]


def test_undo_non_admin_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_undo_last(monkeypatch, admin=False)

    result = runner.invoke(cli.app, ["undo"])

    assert result.exit_code == 3
    assert calls == []
    assert "以管理员身份运行" in result.stdout


def test_undo_failure_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_undo_last(
        monkeypatch,
        result=UndoResult("id-1", 0, [(["powercfg"], "退出码 1")], "回滚失败"),
    )

    result = runner.invoke(cli.app, ["undo"])

    assert result.exit_code == 2
    assert "失败 powercfg" in result.stdout


def test_undo_internal_error_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_undo_last(monkeypatch, error=RuntimeError("炸了"))

    result = runner.invoke(cli.app, ["--json", "undo"])

    assert result.exit_code == 4
    assert result.stdout == ""
    assert "内部错误" in result.stderr


def test_undo_json_stdout_is_only_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_undo_last(monkeypatch, result=UndoResult("id-1", 2, [], "已回滚 2 条命令"))

    result = runner.invoke(cli.app, ["undo", "last", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["change_id"] == "id-1"
    assert payload["executed"] == 2
    assert payload["failed"] == []
    assert payload["message"] == "已回滚 2 条命令"


# ---------------------------------------------------------------------------
# undo 层：journal + fake runner
# ---------------------------------------------------------------------------
def test_undo_last_executes_argv_and_marks_undone(tmp_path: Path) -> None:
    journal, change_id = _journal_with(
        tmp_path,
        undo_argv=[["netsh", "restore", "one"], ["powercfg", "restore", "two"]],
    )
    run, calls = _fake_runner()

    result = undo_last(journal=journal, run=run)  # type: ignore[arg-type]

    assert result.change_id == change_id
    assert result.executed == 2
    assert result.failed == []
    assert calls == [["netsh", "restore", "one"], ["powercfg", "restore", "two"]]
    current = journal.get(change_id)
    assert current is not None
    assert current.status is ChangeStatus.undone


def test_undo_stops_on_failure_and_keeps_applied(tmp_path: Path) -> None:
    journal, change_id = _journal_with(
        tmp_path,
        undo_argv=[["netsh", "ok"], ["netsh", "bad"], ["netsh", "never"]],
    )
    run, calls = _fake_runner({("netsh", "bad"): (1, "拒绝访问")})

    result = undo_last(journal=journal, run=run)  # type: ignore[arg-type]

    assert result.change_id == change_id
    assert result.executed == 1
    assert len(result.failed) == 1
    failed_argv, failed_reason = result.failed[0]
    assert failed_argv == ["netsh", "bad"]
    assert "退出码 1" in failed_reason
    assert calls == [["netsh", "ok"], ["netsh", "bad"]], "失败后不得继续执行后续 argv"
    current = journal.get(change_id)
    assert current is not None
    assert current.status is ChangeStatus.applied, "失败时不得标记 undone"


def test_undo_without_steps_does_not_execute(tmp_path: Path) -> None:
    journal, change_id = _journal_with(tmp_path, undo_argv=[])
    run, calls = _fake_runner()

    result = undo_last(journal=journal, run=run)  # type: ignore[arg-type]

    assert result.change_id == change_id
    assert result.executed == 0
    assert result.message == "该变更没有可自动回滚的步骤"
    assert calls == []
    current = journal.get(change_id)
    assert current is not None
    assert current.status is ChangeStatus.applied


def test_undo_last_without_records(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "changes.jsonl")
    run, calls = _fake_runner()

    result = undo_last(journal=journal, run=run)  # type: ignore[arg-type]

    assert result.change_id is None
    assert result.executed == 0
    assert result.failed == []
    assert result.message == "没有可回滚的变更"
    assert calls == []


def test_undo_last_filters_by_kind(tmp_path: Path) -> None:
    journal, dns_id = _journal_with(tmp_path, undo_argv=[["netsh", "dns"]], kind="dns")
    power = journal.begin(
        kind="power",
        target="powercfg",
        before={},
        after={},
        undo=[["powercfg", "undo"]],
    )
    journal.complete(power.id)
    run, calls = _fake_runner()

    result = undo_last(kind="dns", journal=journal, run=run)  # type: ignore[arg-type]

    assert result.change_id == dns_id
    assert calls == [["netsh", "dns"]]
    assert journal.get(dns_id).status is ChangeStatus.undone  # type: ignore[union-attr]
    assert journal.get(power.id).status is ChangeStatus.applied  # type: ignore[union-attr]


def test_undo_by_id(tmp_path: Path) -> None:
    journal, change_id = _journal_with(tmp_path, undo_argv=[["netsh", "undo"]])
    run, _ = _fake_runner()

    result = undo(change_id, journal=journal, run=run)  # type: ignore[arg-type]

    assert result.change_id == change_id
    assert result.executed == 1


def test_undo_unknown_id_is_noop(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "changes.jsonl")
    run, calls = _fake_runner()

    result = undo("missing", journal=journal, run=run)  # type: ignore[arg-type]

    assert result.change_id is None
    assert result.message == "没有可回滚的变更"
    assert calls == []


def test_undo_ignores_non_applied_record(tmp_path: Path) -> None:
    """只有 intent、没 complete 的记录不能回滚。"""
    journal, change_id = _journal_with(
        tmp_path,
        undo_argv=[["netsh", "undo"]],
        applied=False,
    )
    run, calls = _fake_runner()

    result = undo_last(journal=journal, run=run)  # type: ignore[arg-type]

    assert result.change_id is None
    assert result.message == "没有可回滚的变更"
    assert calls == []
    assert journal.get(change_id).status is ChangeStatus.intent  # type: ignore[union-attr]
