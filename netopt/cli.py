# -*- coding: utf-8 -*-
"""v2 CLI 入口（typer）。

只做三件事：解析全局选项、把命令分发给 ``netopt.commands``、把结果渲染到终端。
渲染实现属于 ``netopt.render``；本模块不解析原始命令输出、不持有任何阈值。

退出码（``docs/SPEC.md`` §10）：

======  ==========================================
0       完成，无 critical finding
1       用法错误
2       完成，但有 critical finding
3       需要管理员权限
4       内部错误
======  ==========================================

``--json`` 时 stdout **只有** JSON；错误提示一律写 stderr。
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import typer
from pydantic import BaseModel, TypeAdapter, ValidationError
from rich.console import Console
from rich.text import Text

import netopt
from netopt import config as config_mod
from netopt import update as update_mod
from netopt.commands import auto as auto_cmd
from netopt.commands import dns as dns_cmd
from netopt.commands import fix as fix_cmd
from netopt.commands import full as full_cmd
from netopt.commands import health as health_cmd
from netopt.commands import http as http_cmd
from netopt.commands import ping as ping_cmd
from netopt.commands import speed as speed_cmd
from netopt.commands import status as status_cmd
from netopt.commands import trace as trace_cmd
from netopt.commands import undo as undo_cmd
from netopt.commands import watch as watch_cmd
from netopt.commands import wifi as wifi_cmd
from netopt.commands.fix import FixKind, FixResult
from netopt.commands.undo import UndoResult
from netopt.domain import Finding, FindingCode, ProbeError, Report, Severity
from netopt.domain.codes import ProbeErrorCode

#: 退出码（与 ``docs/SPEC.md`` §10 一致）。
EXIT_OK = 0
EXIT_USAGE = 1
EXIT_CRITICAL = 2
EXIT_PERMISSION = 3
EXIT_INTERNAL = 4

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Windows 网络诊断与优化工具（v2）",
)


@app.callback()
def _global_options(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json/--no-json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="禁用彩色输出（等价于设置 NO_COLOR=1）",
    ),
    portable: bool = typer.Option(
        False,
        "--portable",
        help="便携模式：运行期目录放到程序根目录（设置 NETOPT_HOME）",
    ),
) -> None:
    """解析全局选项并放进 ``ctx.obj``。

    ``--portable`` 必须在任何命令执行前生效，因此放在 callback 里直接设置
    ``NETOPT_HOME``；``netopt.paths`` 是调用时才解析环境变量的，命令层无需
    感知这个选项。
    """
    ctx.obj = {"json": json_output, "no_color": no_color, "portable": portable}
    if no_color:
        # 只在用户显式要求时设置，避免覆盖调用方已有的 NO_COLOR
        os.environ.setdefault("NO_COLOR", "1")
    if portable:
        # 显式覆盖：便携模式优先于调用方已有的 NETOPT_HOME（见 paths.app_dir）
        os.environ["NETOPT_HOME"] = str(Path(netopt.__file__).resolve().parent.parent)


def _render_json(report: Any) -> str:
    """JSON 渲染：直接复用 :func:`netopt.render.json.render_json`。"""
    from netopt.render.json import render_json

    return render_json(report)


def _render_text(report: Any) -> None:
    """终端渲染：直接复用 :func:`netopt.render.text.render_report`。"""
    from netopt.render.text import render_report

    render_report(report)


def _exit_code(report: Any) -> int:
    """把 Report 映射成 SPEC §10 的退出码。

    权限错误（``denied``）优先于 critical：它决定了命令能否给出可信结果。
    比较走 :class:`ProbeErrorCode` 常量而非裸字符串；依赖方向见 tach.toml
    中的 ``netopt.cli`` 条目（允许依赖 ``netopt.domain``）。
    """
    if any(error.code == ProbeErrorCode.DENIED for error in report.errors):
        return EXIT_PERMISSION
    if report.critical_findings():
        return EXIT_CRITICAL
    return EXIT_OK


# ---------------------------------------------------------------------------
# 修复 / 回滚：结果序列化与文本渲染
# ---------------------------------------------------------------------------
#: 非管理员时的统一提示（文案里必须有「以管理员身份运行」）。
_PERMISSION_MESSAGE = "需要管理员权限，请以管理员身份运行"

#: Finding 严重程度 → 颜色，语义与 ``netopt.render.text`` 一致。
_SEVERITY_STYLE = {
    Severity.ok: "green",
    Severity.info: "cyan",
    Severity.warn: "yellow",
    Severity.critical: "red",
}


def _jsonable(value: Any) -> Any:
    """把 dataclass / pydantic 模型 / datetime 递归转成可 JSON 序列化的对象。

    ``FixResult`` 是 dataclass，但其中的 ``findings`` 是 pydantic 模型；
    ``dataclasses.asdict`` 不会处理它们，因此这里显式递归。
    """
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _jsonable(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def _emit_json(value: Any) -> None:
    """输出单行 JSON；stdout 只有 JSON，提示一律走 stderr。"""
    typer.echo(json.dumps(_jsonable(value), ensure_ascii=False))


def _render_fix_text(result: FixResult) -> None:
    """把修复结果按「每步一行」渲染：跳过 / 已应用 / 失败 + 结论。"""
    console = Console()
    if result.dry_run:
        console.print(Text("dry-run：未执行任何修改", style="yellow"))
    for target in result.skipped:
        console.print(Text(f"跳过 {target}（已是目标状态）", style="dim"))
    for change_id in result.applied:
        console.print(Text(f"已应用 {change_id}", style="green"))
    for change_id, error in result.failed:
        label = change_id or "（未写入日志）"
        console.print(Text(f"失败 {label}: {error}", style="red"))
    for finding in result.findings:
        style = _SEVERITY_STYLE[finding.severity]
        console.print(Text(f"{finding.title}：{finding.detail}", style=style))


def _render_undo_text(result: UndoResult) -> None:
    """把回滚结果渲染成终端文本：失败行红色，其余按结果着色。"""
    console = Console()
    if result.change_id is not None:
        console.print(Text(f"变更：{result.change_id}", style="bold"))
    for argv, error in result.failed:
        console.print(Text(f"失败 {' '.join(argv)}: {error}", style="red"))
    if result.failed:
        style = "red"
    elif result.change_id is not None:
        style = "green"
    else:
        style = "dim"
    console.print(Text(result.message, style=style))


def _permission_fix_result(kind: FixKind) -> FixResult:
    """非管理员且非 dry-run 时返回的结果：**不执行任何写操作**。"""
    return FixResult(
        kind=kind,
        applied=[],
        failed=[],
        skipped=[],
        findings=[
            Finding(
                code=FindingCode.PERMISSION_DENIED,
                severity=Severity.warn,
                title="需要管理员权限",
                detail=f"{_PERMISSION_MESSAGE}；本次未执行任何修改。",
                advice=["右键以管理员身份打开终端后重试", "或先使用 --dry-run 查看计划"],
            )
        ],
    )


def _permission_undo_result() -> UndoResult:
    """非管理员时回滚命令的结果：不执行任何命令。"""
    return UndoResult(
        change_id=None,
        executed=0,
        failed=[],
        message=f"{_PERMISSION_MESSAGE}；本次未执行任何回滚。",
    )


def _fix_exit_code(result: FixResult) -> int:
    """修复结果的退出码：有失败项 → 2，否则 0（SPEC §10）。"""
    return EXIT_CRITICAL if result.failed else EXIT_OK


def _undo_exit_code(result: UndoResult) -> int:
    """回滚结果的退出码：有失败项 → 2，否则 0（SPEC §10）。"""
    return EXIT_CRITICAL if result.failed else EXIT_OK


def _run_fix(kind_text: str, *, dry_run: bool, restore: bool, json_output: bool) -> int:
    """解析 ``kind``、检查权限、执行修复或还原，并返回退出码。

    ``--restore`` 沿用 v1 语义：等价于 ``undo_last(kind="dns")``。
    ``--dry-run`` 不执行任何命令，因此也不需要管理员权限。
    """
    try:
        kind = FixKind(kind_text.strip().lower())
    except ValueError:
        print(
            f"用法错误: 未知的修复类型 {kind_text!r}；可选 dns / tcp / power / all",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        if restore:
            if dry_run:
                undo_result = UndoResult(
                    change_id=None,
                    executed=0,
                    failed=[],
                    message="dry-run：未执行任何修改",
                )
                if json_output:
                    _emit_json(undo_result)
                else:
                    _render_undo_text(undo_result)
                return EXIT_OK
            if not undo_cmd.is_admin():
                permission = _permission_undo_result()
                if json_output:
                    _emit_json(permission)
                else:
                    _render_undo_text(permission)
                return EXIT_PERMISSION
            undo_result = undo_cmd.undo_last(kind="dns")
            if json_output:
                _emit_json(undo_result)
            else:
                _render_undo_text(undo_result)
            return _undo_exit_code(undo_result)

        if not dry_run and not undo_cmd.is_admin():
            fix_permission = _permission_fix_result(kind)
            if json_output:
                _emit_json(fix_permission)
            else:
                _render_fix_text(fix_permission)
            return EXIT_PERMISSION

        result = fix_cmd.apply_fix(kind, dry_run=dry_run)
        if json_output:
            _emit_json(result)
        else:
            _render_fix_text(result)
        return _fix_exit_code(result)
    except PermissionError as exc:
        print(f"需要管理员权限: {exc}", file=sys.stderr)
        return EXIT_PERMISSION
    except Exception as exc:  # 顶层命令边界，保证退出码可预期
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


def _run_undo(change_id: str, *, json_output: bool) -> int:
    """执行 ``undo last`` / ``undo <id>`` 并返回退出码。

    回滚同样会写系统设置，因此非管理员一律在动手前返回 3。
    """
    try:
        if not undo_cmd.is_admin():
            result = _permission_undo_result()
            if json_output:
                _emit_json(result)
            else:
                _render_undo_text(result)
            return EXIT_PERMISSION

        result = undo_cmd.undo_last() if change_id == "last" else undo_cmd.undo(change_id)
        if json_output:
            _emit_json(result)
        else:
            _render_undo_text(result)
        return _undo_exit_code(result)
    except PermissionError as exc:
        print(f"需要管理员权限: {exc}", file=sys.stderr)
        return EXIT_PERMISSION
    except Exception as exc:  # 顶层命令边界，保证退出码可预期
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


def _watch_score(sample: watch_cmd.WatchSample) -> int | None:
    """样本的健康总分；报告没有评分时返回 ``None``（不拿 0 冒充）。"""
    score = sample.report.score
    return None if score is None else score.total


def _watch_score_text(sample: watch_cmd.WatchSample) -> str:
    """样本分数的展示文本；没有评分时用 ``-``（不拿 0 冒充）。"""
    total = _watch_score(sample)
    return "-" if total is None else str(total)


def _print_watch_line(sample: watch_cmd.WatchSample) -> None:
    """逐轮打印一行：时间 / 分数 / 告警数。"""
    Console().print(
        Text(f"{sample.ts}  分数 {_watch_score_text(sample)}  告警 {len(sample.alerts)}")
    )


def _watch_totals(samples: list[watch_cmd.WatchSample]) -> tuple[int, list[int], int]:
    """汇总轮数、有评分的分数列表与告警总数。"""
    scores = [total for sample in samples if (total := _watch_score(sample)) is not None]
    alerts = sum(len(sample.alerts) for sample in samples)
    return len(samples), scores, alerts


def _print_watch_summary(count: int, scores: list[int], alerts: int) -> None:
    """打印结束汇总；平均分只统计有评分的轮次，告警是各轮实际发出之和。"""
    console = Console()
    if count == 0:
        console.print(Text("采样结束：共 0 轮", style="dim"))
        return
    average = f"{sum(scores) / len(scores):.1f}" if scores else "-"
    console.print(
        Text(
            f"采样结束：共 {count} 轮，平均分 {average}，告警 {alerts} 条",
            style="bold",
        )
    )


def _run_watch(
    *,
    interval: float,
    count: int | None,
    out_path: Path | None,
    json_output: bool,
) -> int:
    """运行采样命令并返回退出码。

    ``--json`` 必须配合 ``--count``：否则采样无界、JSON 也只能在结束时
    一次性输出，属于用法错误（退出 1）。采样层面的 ``ValueError`` 同样
    映射为用法错误；其它异常按内部错误处理（退出 4）。

    文本模式通过 ``on_sample`` **逐轮**打印，并且 ``collect=False``：常驻
    采样不累积样本，内存不随轮数增长；结束汇总用回调里累计的统计量。
    JSON 模式仍需完整样本列表，因此保持默认的 ``collect=True``。
    """
    if interval < 0:
        print(f"用法错误: --interval 不能为负数: {interval}", file=sys.stderr)
        return EXIT_USAGE
    if count is not None and count < 0:
        print(f"用法错误: --count 不能为负数: {count}", file=sys.stderr)
        return EXIT_USAGE
    if json_output and count is None:
        print("用法错误: --json 需要同时指定 --count（避免无界输出）", file=sys.stderr)
        return EXIT_USAGE

    streamed: list[watch_cmd.WatchSample] = []

    def on_sample(sample: watch_cmd.WatchSample) -> None:
        # JSON 模式只在结束时一次性输出，回调里不打印也不额外留引用。
        if json_output:
            return
        streamed.append(sample)
        _print_watch_line(sample)

    # 文本模式关闭累积（常驻不爆内存）；JSON 模式保留默认 collect=True。
    extra: dict[str, Any] = {} if json_output else {"collect": False}

    try:
        samples = watch_cmd.run_watch(
            interval=interval,
            count=count,
            out_path=out_path,
            on_sample=on_sample,
            **extra,
        )
    except KeyboardInterrupt:
        # 无 --count 时常驻采样靠 Ctrl+C 结束；已写入的 JSONL 保留，不再补汇总。
        print("已中断", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print(f"用法错误: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # 顶层命令边界，保证退出码可预期
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    try:
        if json_output:
            _emit_json(samples)
            displayed = samples
        else:
            # 命令层的 fake 可能直接返回样本而没有触发回调：补印未流式输出的部分。
            for sample in samples[len(streamed) :]:
                _print_watch_line(sample)
            displayed = samples if samples else streamed
            _print_watch_summary(*_watch_totals(displayed))
    except Exception as exc:  # 渲染失败同样归为内部错误
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    return EXIT_CRITICAL if any(s.report.critical_findings() for s in displayed) else EXIT_OK


def _permission_auto_report() -> Report:
    """非管理员时 ``auto`` 的占位报告：**不探测、不修复、不写 journal**。"""
    message = f"{_PERMISSION_MESSAGE}；本次未执行任何修复。"
    return Report(
        command="auto",
        started_at=datetime.now(UTC),
        duration_ms=0,
        environment={},
        sections=[],
        findings=[
            Finding(
                code=FindingCode.PERMISSION_DENIED,
                severity=Severity.warn,
                title="需要管理员权限",
                detail=message,
                advice=["右键以管理员身份打开终端后重试"],
            )
        ],
        errors=[
            ProbeError(
                code=ProbeErrorCode.DENIED.value,
                source="auto",
                message=message,
                retryable=False,
            )
        ],
        score=None,
    )


def _run_auto(*, json_output: bool, dry_run: bool = False) -> int:
    """执行 ``auto``：权限门通过后才进行诊断与修复（SPEC §10）。

    ``--dry-run`` 只做诊断并生成修复计划，不执行任何写操作，因此不需要
    管理员权限；真正的修复路径仍然要求管理员。
    """
    if not dry_run and not undo_cmd.is_admin():
        report = _permission_auto_report()
        try:
            if json_output:
                typer.echo(_render_json(report))
            else:
                _render_text(report)
        except Exception as exc:  # 渲染失败同样归为内部错误
            print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
            return EXIT_INTERNAL
        return EXIT_PERMISSION
    if dry_run:
        # 用 lambda 包一层：命令层 builder 在调用时才解析，便于测试替换。
        return _run_report(lambda: auto_cmd.build_auto_report(dry_run=True), json_output)
    return _run_report(auto_cmd.build_auto_report, json_output)


# ---------------------------------------------------------------------------
# 配置：config get / set / path
# ---------------------------------------------------------------------------
def _describe_config_error(exc: BaseException) -> str:
    """把 pydantic 校验错误压成一行；其它异常直接用 ``str``。"""
    if isinstance(exc, ValidationError):
        details = exc.errors()
        if details:
            first = details[0]
            location = ".".join(str(part) for part in first.get("loc", ()))
            message = str(first.get("msg", ""))
            return f"{location}: {message}" if location else message
    return str(exc)


def _split_config_key(key: str) -> list[str]:
    """把点号键拆成路径段；空段（``a..b`` / 首尾点号）视为非法。"""
    parts = [part.strip() for part in key.split(".")]
    if not parts or any(not part for part in parts):
        raise ValueError(f"非法配置键: {key!r}")
    return parts


def _leaf_annotation(model: type[BaseModel], parts: list[str]) -> Any:
    """沿点号键找到叶子字段的注解；未知键或把标量当分组时抛 ``ValueError``。"""
    current: type[BaseModel] = model
    prefix = ""
    for part in parts[:-1]:
        field = current.model_fields.get(part)
        if field is None:
            raise ValueError(f"未知配置项: {prefix}{part}")
        annotation = field.annotation
        if not (isinstance(annotation, type) and issubclass(annotation, BaseModel)):
            raise ValueError(f"未知配置项: {prefix}{part}.{parts[-1]}（{part} 不是配置分组）")
        prefix = f"{prefix}{part}."
        current = annotation
    leaf = current.model_fields.get(parts[-1])
    if leaf is None:
        raise ValueError(f"未知配置项: {prefix}{parts[-1]}")
    return leaf.annotation


def _assign_setting(data: dict[str, Any], parts: list[str], value: Any) -> None:
    """把值写进嵌套字典；中间层缺失时补空表。"""
    table = data
    for part in parts[:-1]:
        nested = table.get(part)
        if not isinstance(nested, dict):
            nested = {}
            table[part] = nested
        table = nested
    table[parts[-1]] = value


def _parse_setting_value(text: str, annotation: Any) -> Any:
    """按字段注解解析命令行字符串。

    先让 pydantic 直接吃原始字符串（兼容 ``120`` / ``1.5`` / ``true``）；
    失败后按 JSON 再试一次（列表、对象与带引号的字符串）。两次都失败时
    抛 :class:`ValueError`，由调用方映射成退出码 1。
    """
    adapter = TypeAdapter(annotation)
    try:
        return adapter.validate_python(text)
    except ValidationError:
        pass
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"配置值无法解析（期望 {annotation}）: {text!r}") from exc
    try:
        return adapter.validate_python(parsed)
    except ValidationError as exc:
        raise ValueError(f"配置值非法（期望 {annotation}）: {text!r}") from exc


def _flatten_settings(data: dict[str, Any], prefix: str = "") -> list[tuple[str, Any]]:
    """把嵌套配置摊平成 ``(点号键, 值)``，保持模型字段顺序。"""
    flat: list[tuple[str, Any]] = []
    for key, value in data.items():
        dotted = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.extend(_flatten_settings(value, f"{dotted}."))
        else:
            flat.append((dotted, value))
    return flat


def _render_settings_text(settings: config_mod.Settings) -> None:
    """文本输出：每行 ``点号键 = JSON 值``，字符串带引号、中文原样。

    用 ``typer.echo`` 而不是 rich：配置值里可能有方括号 / 花括号，rich 的
    标记解析与软换行只会让输出更难读。
    """
    for key, value in _flatten_settings(settings.model_dump()):
        typer.echo(f"{key} = {json.dumps(value, ensure_ascii=False)}")


def _run_config_get(json_output: bool) -> int:
    """读取配置并输出；配置文件损坏时按用法错误处理（退出 1）。"""
    try:
        settings = config_mod.load()
    except (OSError, ValueError) as exc:
        print(f"配置错误: {_describe_config_error(exc)}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if json_output:
            _emit_json(settings)
        else:
            _render_settings_text(settings)
    except Exception as exc:  # 渲染失败同样归为内部错误
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    return EXIT_OK


def _run_config_set(key: str, value: str) -> int:
    """校验点号键与新值后写回 ``config.toml``；非法键/值一律退出 1。"""
    try:
        settings = config_mod.load()
        data = settings.model_dump()
        parts = _split_config_key(key)
        annotation = _leaf_annotation(config_mod.Settings, parts)
        _assign_setting(data, parts, _parse_setting_value(value, annotation))
        updated = config_mod.Settings.model_validate(data)
    except (OSError, ValueError) as exc:
        print(f"配置错误: {_describe_config_error(exc)}", file=sys.stderr)
        return EXIT_USAGE
    try:
        config_mod.save(updated)
    except OSError as exc:
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    typer.echo(f"已设置 {key} = {value}")
    return EXIT_OK


def _run_config_path() -> int:
    """打印实际配置文件路径。

    路径解析属于配置层：这里复用 :mod:`netopt.config` 已导入的 ``paths``，
    避免 CLI 直接依赖 ``netopt.paths``（tach 的分层清单只登记了 config）。
    """
    typer.echo(str(config_mod.paths.config_path()))
    return EXIT_OK


# ---------------------------------------------------------------------------
# 更新检查
# ---------------------------------------------------------------------------
def _render_update_text(info: update_mod.UpdateInfo) -> None:
    """文本输出：当前版本、最新版本 / 检查失败原因与下载地址。"""
    console = Console()
    console.print(Text(f"当前版本：{info.current}"))
    if info.error is not None:
        console.print(Text(f"检查失败：{info.error}", style="red"))
        return
    if info.latest is not None:
        console.print(Text(f"最新版本：{info.latest}"))
    if info.available:
        console.print(Text("发现新版本", style="yellow"))
        if info.url:
            console.print(Text(f"下载：{info.url}"))
    else:
        console.print(Text("已是最新版本", style="green"))


def _run_update(*, json_output: bool, strict: bool) -> int:
    """调用 :func:`netopt.update.check` 并输出结果。

    检查失败（网络 / 解析）默认仍返回 0，与 :mod:`netopt.update` 的
    「只提示、不报错」约定一致；``--strict`` 时以退出码 2 结束，便于脚本
    判断「没检查成功」。
    """
    try:
        info = update_mod.check()
    except Exception as exc:  # update.check 已内部兜底，这里只做最后一道边界
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    try:
        if json_output:
            _emit_json(info)
        else:
            _render_update_text(info)
    except Exception as exc:
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    if strict and info.error is not None:
        return EXIT_CRITICAL
    return EXIT_OK


def _run_report(builder: Callable[[], Report], json_output: bool) -> int:
    """构建报告、渲染并返回退出码（所有「探测 → Report」命令共用）。

    ``builder`` 必须是**调用时**才解析的零参可调用对象：命令函数用 lambda
    把 ``target`` 等参数包进去，这样测试 monkeypatch 命令层 builder 才能生效。

    失败处理：

    - ``PermissionError`` → 3（需要管理员权限，SPEC §10）；
    - 其它构建 / 渲染异常 → 4（内部错误），错误信息只写 stderr；
    - ``--json`` 时 stdout 只写 JSON，绝不夹带提示行。
    """
    try:
        report = builder()
    except PermissionError as exc:
        print(f"需要管理员权限: {exc}", file=sys.stderr)
        return EXIT_PERMISSION
    except Exception as exc:  # 顶层命令边界，保证退出码可预期
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    try:
        if json_output:
            typer.echo(_render_json(report))
        else:
            _render_text(report)
    except Exception as exc:  # 渲染失败同样归为内部错误
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    return _exit_code(report)


@app.command("status")
def status_command(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """快速诊断：网关 / 外网 / DNS / HTTP / MTU。"""
    options = ctx.obj or {}
    code = _run_report(
        status_cmd.build_status_report,
        bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("health")
def health_command(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """健康评分：网关 / 外网 / DNS / HTTP / MTU 五项加权。"""
    options = ctx.obj or {}
    code = _run_report(
        health_cmd.build_health_report,
        bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("ping")
def ping_command(
    ctx: typer.Context,
    target: str | None = typer.Argument(
        None,
        help="目标主机；缺省使用命令层默认值（www.baidu.com）",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """延迟测试：网关 + 目标主机的 ping 延迟与丢包。"""
    options = ctx.obj or {}
    code = _run_report(
        lambda: ping_cmd.build_ping_report(target),
        bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("dns")
def dns_command(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """DNS 基准：公共 DNS + 当前系统 DNS 的解析耗时对比。"""
    options = ctx.obj or {}
    code = _run_report(
        dns_cmd.build_dns_report,
        bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("http")
def http_command(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """HTTP 测试：4 个常用站点的 HTTPS 首字节耗时。"""
    options = ctx.obj or {}
    code = _run_report(
        http_cmd.build_http_report,
        bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("speed")
def speed_command(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """带宽测速：多源下载 + 上传吞吐。"""
    options = ctx.obj or {}
    code = _run_report(
        speed_cmd.build_speed_report,
        bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("trace")
def trace_command(
    ctx: typer.Context,
    target: str | None = typer.Argument(
        None,
        help="目标主机；缺省使用命令层默认值（www.baidu.com）",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """路由追踪：按跳展示 tracert 原始输出。"""
    options = ctx.obj or {}
    code = _run_report(
        lambda: trace_cmd.build_trace_report(target),
        bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("wifi")
def wifi_command(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """WiFi 状态：当前连接、信号强度与信道占用。"""
    options = ctx.obj or {}
    code = _run_report(
        wifi_cmd.build_wifi_report,
        bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("full")
def full_command(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """全面诊断：status + speed + trace + wifi 合成一份报告。"""
    options = ctx.obj or {}
    code = _run_report(
        full_cmd.build_full_report,
        bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("watch")
def watch_command(
    ctx: typer.Context,
    interval: float = typer.Option(5.0, "--interval", help="采样间隔（秒）"),
    count: int | None = typer.Option(
        None,
        "--count",
        help="采样轮数；缺省一直采样（Ctrl+C 停止）",
    ),
    out: str | None = typer.Option(
        None,
        "--out",
        help="JSONL 输出路径；缺省写到 state/metrics.jsonl",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出全部样本（必须同时指定 --count）",
    ),
) -> None:
    """常驻采样：每轮 status → 告警去抖 → 追加 metrics.jsonl。"""
    options = ctx.obj or {}
    code = _run_watch(
        interval=interval,
        count=count,
        out_path=None if out is None else Path(out),
        json_output=bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("monitor")
def monitor_command(
    count: int = typer.Option(60, "--count", "-n", help="采样轮数"),
    interval: float = typer.Option(1.0, "--interval", help="采样间隔（秒）"),
) -> None:
    """持续采样：等价于 ``watch --interval 1 --count 60``（文本输出）。"""
    code = _run_watch(
        interval=interval,
        count=count,
        out_path=None,
        json_output=False,
    )
    raise typer.Exit(code)


@app.command("auto")
def auto_command(
    ctx: typer.Context,
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="只生成修复计划，不执行任何修改（无需管理员）",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出报告（stdout 只有 JSON）",
    ),
) -> None:
    """一键优化：诊断 → 自动修复全部 → 复测（需管理员）。"""
    options = ctx.obj or {}
    code = _run_auto(
        json_output=bool(json_output or options.get("json")),
        dry_run=dry_run,
    )
    raise typer.Exit(code)


@app.command("fix")
def fix_command(
    ctx: typer.Context,
    kind: str = typer.Argument("all", help="修复类别：dns / tcp / power / all"),
    dry_run: bool = typer.Option(False, "--dry-run", help="只生成计划，不执行任何修改"),
    restore: bool = typer.Option(
        False,
        "--restore",
        help="还原 DNS（等价于 undo last，仅针对 dns 类型）",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出结果（stdout 只有 JSON）",
    ),
) -> None:
    """执行网络修复（需管理员；``--dry-run`` 除外）。"""
    options = ctx.obj or {}
    code = _run_fix(
        kind,
        dry_run=dry_run,
        restore=restore,
        json_output=bool(json_output or options.get("json")),
    )
    raise typer.Exit(code)


@app.command("undo")
def undo_command(
    ctx: typer.Context,
    change_id: str = typer.Argument(
        "last",
        help="变更 ID；last 表示最近一次已应用的变更",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出结果（stdout 只有 JSON）",
    ),
) -> None:
    """回滚最近一次或指定 ID 的修复（需管理员）。"""
    options = ctx.obj or {}
    code = _run_undo(change_id, json_output=bool(json_output or options.get("json")))
    raise typer.Exit(code)


# ---------------------------------------------------------------------------
# config / update 命令
# ---------------------------------------------------------------------------
config_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="查看与修改配置（config.toml）",
)
app.add_typer(config_app, name="config")


@config_app.command("get")
def config_get_command(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出配置（stdout 只有 JSON）",
    ),
) -> None:
    """读取当前配置（含环境变量覆盖）。"""
    options = ctx.obj or {}
    raise typer.Exit(_run_config_get(bool(json_output or options.get("json"))))


@config_app.command("set")
def config_set_command(
    key: str = typer.Argument(..., help="点号键，例如 policy.wan.warn / language"),
    value: str = typer.Argument(
        ...,
        help='新值；列表与对象用 JSON（如 \'["a", "b"]\'）',
    ),
) -> None:
    """校验并写回一个配置项（非法键/值退出 1）。"""
    raise typer.Exit(_run_config_set(key, value))


@config_app.command("path")
def config_path_command() -> None:
    """打印实际配置文件路径。"""
    raise typer.Exit(_run_config_path())


@app.command("update")
def update_command(
    ctx: typer.Context,
    strict: bool = typer.Option(
        False,
        "--strict",
        help="检查失败时以退出码 2 结束",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="以 JSON 输出检查结果（stdout 只有 JSON）",
    ),
) -> None:
    """检查是否有新版本（只读查询 GitHub Releases）。"""
    options = ctx.obj or {}
    raise typer.Exit(
        _run_update(
            json_output=bool(json_output or options.get("json")),
            strict=strict,
        )
    )


@app.command("version")
def version_command() -> None:
    """打印版本号。"""
    typer.echo(f"net-optimizer {netopt.VERSION}")


def main(argv: list[str] | None = None) -> int:
    """运行 CLI 并返回退出码（供 ``netoptimizer.py`` 兼容壳调用）。

    ``standalone_mode=False`` 让 typer 不直接 ``sys.exit``：命令显式抛
    :class:`typer.Exit` 时返回其退出码；参数用法错误（``UsageError``）在非
    standalone 模式下会被重新抛出，这里统一映射为 1。
    """
    try:
        result = app(args=argv, prog_name="netopt", standalone_mode=False)
    except typer.Exit as exc:
        return int(exc.exit_code)
    except typer.Abort:
        typer.echo("已中断", err=True)
        return EXIT_USAGE
    except Exception as exc:
        # typer 0.27 内置 click；用法错误对象带 ``exit_code`` 与 ``show()``。
        # click 传统上把用法错误映射为 2，本项目的 SPEC §10 规定为 1，这里统一。
        show = getattr(exc, "show", None)
        if isinstance(getattr(exc, "exit_code", None), int) and callable(show):
            show()
            return EXIT_USAGE
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    return int(result) if isinstance(result, int) else 0


__all__ = ["app", "main"]
