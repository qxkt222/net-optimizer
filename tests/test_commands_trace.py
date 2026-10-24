# -*- coding: utf-8 -*-
"""``netopt.commands.trace`` 测试：``tracert`` → Report，不打印、不解析跳数。

**绝不执行系统命令**：所有用例都给 :func:`build_trace_report` 注入 fake runner；
``conftest`` 的 autouse 夹具会拦截任何漏注入的真实调用。
"""

from __future__ import annotations

import inspect

from netopt.commands import trace as trace_mod
from netopt.commands.trace import DEFAULT_TARGET, TRACE_FAILED, build_trace_report
from netopt.domain import ProbeErrorCode, Severity
from netopt.platform import CmdResult

#: 固定三行样本（第一跳 / 第二跳 / 超时跳）。
_TRACE_OK = "  1     1 ms   192.0.2.1\n  2     8 ms   198.51.100.1\n  3     *        *        *\n"


def _section(report):
    return report.sections[0]


def _codes(report) -> set[str]:
    """顶层与本节结论码的并集（两条路径都要能查到）。"""
    return {finding.code for finding in report.findings} | {
        finding.code for finding in _section(report).findings
    }


def _finding(report, code: str):
    return next(finding for finding in report.findings if finding.code == code)


# ===========================================================================
# 成功：逐行保留原文
# ===========================================================================
def test_trace_success_keeps_each_line_in_rows(fake_run, capsys) -> None:
    run = fake_run({("tracert",): (_TRACE_OK, 0)})

    report = build_trace_report("www.baidu.com", run=run)

    assert report.command == "trace"
    assert report.schema_version == 1
    assert report.duration_ms >= 0
    assert {"admin", "python", "platform", "cwd", "api"} <= set(report.environment)
    assert report.environment["api"] == "tracert"
    assert report.findings == []
    assert report.errors == []

    section = _section(report)
    assert section.id == "trace"
    assert section.title == "路由追踪"
    assert section.rows == [
        {"行": "  1     1 ms   192.0.2.1"},
        {"行": "  2     8 ms   198.51.100.1"},
        {"行": "  3     *        *        *"},
    ]
    assert all(set(row) == {"行"} for row in section.rows), "rows 不得使用 key/value 结构"
    assert capsys.readouterr().out == "", "命令层不得打印"


def test_trace_skips_blank_lines_but_keeps_original_text(fake_run) -> None:
    run = fake_run({("tracert",): ("  1     1 ms   192.0.2.1\n\n  2     8 ms   198.51.100.1\n", 0)})

    report = build_trace_report("example.com", run=run)

    assert [row["行"] for row in _section(report).rows] == [
        "  1     1 ms   192.0.2.1",
        "  2     8 ms   198.51.100.1",
    ]


def test_trace_uses_default_target_and_expected_argv(fake_run) -> None:
    run = fake_run({("tracert",): ("  1     1 ms   192.0.2.1\n", 0)})

    report = build_trace_report(run=run)

    assert _section(report).rows == [{"行": "  1     1 ms   192.0.2.1"}]
    assert run.calls[0] == ["tracert", "-d", "-h", "20", "-w", "800", DEFAULT_TARGET]


def test_trace_custom_hops_and_budget_are_passed_through() -> None:
    seen: dict[str, object] = {}

    def runner(argv, timeout=30.0, **kwargs):
        seen["argv"] = list(argv)
        seen["timeout"] = timeout
        return CmdResult(argv=list(argv), code=0, out="body\n")

    build_trace_report("example.com", run=runner, max_hops=5, budget_seconds=42.5)

    assert seen["argv"] == ["tracert", "-d", "-h", "5", "-w", "800", "example.com"]
    assert seen["timeout"] == 42.5


# ===========================================================================
# 失败：Finding + ProbeError
# ===========================================================================
def test_trace_timeout_reports_finding_and_probe_error(fake_run, capsys) -> None:
    run = fake_run({("tracert",): CmdResult(argv=["tracert"], code=-1, out="", timed_out=True)})

    report = build_trace_report("www.baidu.com", run=run)

    assert _section(report).rows == [], "失败时不得把半截输出当作成功结果"
    assert len(report.errors) == 1
    error = report.errors[0]
    assert error.code == ProbeErrorCode.TIMEOUT
    assert error.retryable is True
    assert TRACE_FAILED in _codes(report)
    finding = _finding(report, TRACE_FAILED)
    assert finding.severity is Severity.warn
    assert "超时" in finding.detail
    assert capsys.readouterr().out == "", "命令层不得打印"


def test_trace_missing_command_is_not_retryable(fake_run) -> None:
    run = fake_run(
        {
            ("tracert",): CmdResult(
                argv=["tracert"], code=-1, out="找不到命令：tracert", missing=True
            )
        }
    )

    report = build_trace_report("www.baidu.com", run=run)

    error = report.errors[0]
    assert error.code == ProbeErrorCode.MISSING
    assert error.retryable is False
    assert "tracert" in _finding(report, TRACE_FAILED).detail


def test_trace_nonzero_exit_is_reported_with_first_output_line(fake_run) -> None:
    run = fake_run({("tracert",): ("无法解析目标系统名称。\n", 1)})

    report = build_trace_report("no-such-host.invalid", run=run)

    error = report.errors[0]
    assert error.code == ProbeErrorCode.NETWORK
    assert "rc=1" in error.message
    finding = _finding(report, TRACE_FAILED)
    assert "无法解析目标系统名称" in finding.detail
    assert finding.evidence[0].detail == "无法解析目标系统名称。"
    assert _section(report).rows == []


# ===========================================================================
# 分层约束
# ===========================================================================
def test_trace_does_not_depend_on_diag() -> None:
    """v2 命令层不得回头依赖 v1 的 ``netopt.diag``（禁止打印 / 旧解析）。"""
    source = inspect.getsource(trace_mod)

    assert "netopt.diag" not in source
    assert "import diag" not in source
