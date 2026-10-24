# v2 实现状态

> 分支：`rewrite/v2`。最终快照日期：2026-10-24。
> 基线：v1.1（294 tests / 91% coverage）。
> 本文件只记录**实际验证过**的状态；没跑过、没在真机确认的一律标「待验证」。

## 测试与门禁

| 项 | 数值 | 来源 |
| :--- | :--- | :--- |
| 单元测试 | 1098 passed / 1 skipped | `pytest tests -q`，2026-10-24 |
| 覆盖率 | 93.08%（6100 statements / 422 missed） | `pytest --cov=netopt` |
| 本地门禁 | 7/7，连跑 2 次 | `python run_tests.py`（ruff / format / mypy / tach / bandit / pytest-cov） |
| CI | GitHub Actions `windows-latest` + Python 3.13 + uv | `.github/workflows/ci.yml` |

覆盖率门槛 90%，低于门槛 `run_tests.py` 与 CI 直接失败。

## 构建产物与冒烟

已用 PyInstaller 实际构建并完成命令行冒烟，产物在 `dist/（构建目录）`；
仓库不提交 `dist/` 与 `build/`。

| 文件 | 大小 | 入口 | 控制台 |
| :--- | ---: | :--- | :--- |
| `netopt.exe` | 16,008,226 B（约 16.0 MB） | `netopt/__main__.py` | 有 |
| `NetOptimizer.exe` | 19,064,858 B（约 19.1 MB） | `gui.py` | 无 |

冒烟结果：

- `netopt.exe version` → rc=0。
- `netopt.exe --help` → rc=0，列出 17 个命令。
- `netopt.exe ping 127.0.0.1 --json` → rc=0，stdout 为纯 JSON。
- 真机 smoke：`status` 输出 5 节、0 error；`health` 98 分（优）；`fix dns --dry-run` 零副作用；
  `watch --json` 正常；`update` 遇 404 降级为 `error` 字段；`--portable` 路径指向程序目录。
- `NetOptimizer.exe` 已构建，但**交互流程未人工验证**（见「未完成」）。

## 已完成模块

### domain

- `report.py`：`Report` / `Section` / `Metric` / `Finding` / `ProbeError` / `Evidence` / `Score`，pydantic v2，`frozen=True`。
- `policy.py`：统一的阈值、权重与分档，替代 v1 的四套标准。
- `codes.py`：Finding code 与 ProbeError code 常量。
- `models.py`：进程内 frozen dataclass（Adapter / Address / Route / WifiState 等）。
- `changes.py`：变更记录 `Change` 与 `ChangeStatus`。

### system

- `api.py`：`SystemApi` Protocol、`SystemUnavailable`、`FakeSystemApi`。
- `iphlpapi.py`：`GetAdaptersAddresses` / `GetIpForwardTable2` / `GetBestRoute2` / `GetIfTable2` 的 ctypes 封装与结构体解析。
- `wlanapi.py`：WLAN 接口枚举、当前连接查询、周边扫描。
- `registry.py`：`NameServer` / `DhcpNameServer`，判定 static / dhcp。
- `commands.py`：netsh / powercfg / reg / ping / tracert 子进程封装。
- `journal.py`：JSONL 变更日志，`intent → complete / fail / undone`，写入前 fsync。
- `live.py`：`LiveSystemApi`，按方法惰性加载 DLL，import 阶段不加载。

### probes

> 布局是扁平模块族（`probes.py` + `probes_*.py`），不是 `probes/` 包。

- `probes.py`：ping、接口 / 网关 / DNS 配置读取、legacy MTU、`ProbeContext`（deadline / cancel / 错误收集）。
- `probes_dns.py`：IPv4 / IPv6 双栈；UDP 响应 TC 截断时回落 TCP；失败分类。
- `probes_http.py`：httpx trace 分段计时 connect / TLS / TTFB / total。
- `probes_mtu.py`：总预算内 DF 二分 + 边界确认；超预算返回 `verified=False` 并记 `timeout`。
- `probes_speed.py`：多连接并发（默认 4）聚合吞吐，单连接失败不拖垮整体。

### analysis

- `health.py`：五项加权评分与评级（优 / 良 / 中 / 差），纯函数。
- `diagnose.py`：本地 / 接入 / 骨干归因。
- `alerts.py`：告警规则、冷却与去重（`AlertEngine`）。

### render

- `text.py`：rich 表格与颜色；`render_plain` 输出无 ANSI 纯文本供 GUI 使用。
- `json.py`：直接 `Report.model_dump_json()`，不裁剪字段。

### commands

- 已迁移到 `Report`：`status`、`health`、`ping`、`dns`、`http`、`speed`、`trace`、`wifi`、`full`。
- `fix.py`：DNS / TCP / Power 计划与执行；先写 journal intent 再动手；DNS 只改主接口；支持 `--dry-run`。
- `undo.py`：按 journal 回滚，全部成功才标记 `undone`。
- `watch.py`：采样循环、告警去抖、追加 `metrics.jsonl`；文本模式逐轮输出，`collect=False` 不累积样本。
- `auto.py`：`auto` 编排——修复前健康评分 → `fix all` → 修复后评分，合成 `Report`。

### cli

- `cli.py`：typer 应用，**17 个命令**：`status` / `health` / `ping` / `dns` / `http` / `speed` /
  `trace` / `wifi` / `full` / `watch` / `monitor` / `auto` / `fix` / `undo` / `update` /
  `version` / `config`。`config` 含 `get` / `set` / `path` 三个子命令。
- 全局 `--json` / `--no-color` / `--portable`；退出码 0 / 1 / 2 / 3 / 4。
- `--json` 前后置均可；`monitor` / `version` 不支持后置写法，`config` 只有 `get` 支持。
- `--json` 时 stdout 只有 JSON，错误写 stderr。
- `watch --json` 必须同时指定 `--count`（无界采样无法在结束时一次性输出）。

### gui

- 根目录 `gui.py`：tkinter 界面，按钮直接消费 `Report`；主线程调用 `render_plain` 渲染。
- 已删除 `sys.stdout` 重定向与 ANSI 解析；`tests/test_gui.py` 有回归断言，确保 `gui` 模块不再出现 `Redirector` / `ANSI_RE`。
- 修复 / 还原走 `netopt.commands.fix` 与 `netopt.commands.undo`；非管理员时提权到新控制台。
- 延迟监控在 GUI 内循环调用 `netopt.probes.ping`，支持停止。
- `NetOptimizer.exe` 已构建并完成启动冒烟；按钮交互未人工验证。

### 其他

- `paths.py`：`NETOPT_HOME` / `%LOCALAPPDATA%\net-optimizer` / `--portable` 路径解析，已接入 CLI。
- `history.py`：JSONL 追加、读取、坏行跳过。
- `config.py`：`config.toml` 读写、`NETOPT_` 环境变量覆盖、未知键报错；已接入 `netopt config get|set|path`。
- `update.py`：GitHub Releases 版本检查，只提示不下载；已接入 `netopt update`。
- `packaging/`：`netopt.spec` 与 `netopt-gui.spec`，已实际构建出两份 exe。
- `run_tests.py`：单一门禁入口，7 项全绿。

## 未完成 / 待验证

1. **i18n 未做**：无 gettext、无 en 资源，界面与文案硬编码中文。
2. **live 测试未接 CI**：没有 `@pytest.mark.live` 标记，`test_system_live.py` 只验证导入与协议；CI 不跑真机。
3. **WiFi 真机未验证**：开发机 `netsh wlan show interfaces` 返回「系统上没有无线接口」；已连接与扫描路径只有合成缓冲区 / `FakeSystemApi` 测试。
4. **TCP / 电源回滚不完整**：`query_tcp_settings` / `query_power_settings` 只保存原始文本，原值未解析；TCP 的 undo 为空，电源的 undo 只恢复内置默认值，不等于执行前状态。DNS 可以自动回滚。
5. **GUI exe 交互未人工验证**：`NetOptimizer.exe` 能构建、能启动，但按钮流程、高 DPI、提权与取消未做人工回归；exe 无代码签名。
6. **`update` 当前返回 404**：仓库尚无 Release，检查失败降级为 `error` 字段，不影响其他命令；发布首个 Release 后需复测。
7. **`watch` 未用 rich Live**：文本模式逐轮打印（时间 / 分数 / 告警数），`collect=False` 不累积；SPEC §13 的实时刷新面板未实现。
8. **`dev` / `clear` / `admin` 未迁移**：仍走 `netoptimizer.py` 的 v1 实现；`auto` / `monitor` / `watch` 已转交 v2 CLI。
9. **状态目录双轨**：v2 的 journal / health 历史在 `%LOCALAPPDATA%\net-optimizer`；v1 的 `state.py`（日志、`history.json`、`dev.json`、`dns-backup.json`）仍在程序目录。
10. **v1 `dns-backup.json` 未导入 journal**（T4.2 部分）：v2 `fix dns` / `undo` 使用 journal；旧数据不会自动迁移。
11. **CLI 参数面小于 SPEC §10**：缺 `status --timeout`、`ping -n`、`dns --servers`、`trace -h`、`wifi --scan`。

## 下一步建议

1. **发布首个 Release**：上传两份 exe、给出 SHA-256 与 SmartScreen 说明；随后复测 `update` 的“有新版本 / 已是最新 / 404 降级”三条路径。
2. **干净 Windows 验收**：在无 Python 的机器上运行 `netopt.exe` 与 `NetOptimizer.exe`，人工验证 GUI 按钮、高 DPI、UAC 与取消路径。
3. **补真机与 live CI**：找一台带无线网卡的机器验证 WiFi 已连接 / 扫描；加 `@pytest.mark.live` 与夜间 CI，覆盖 VPN / 仅 IPv6 / 断网。
4. **补全回滚**：解析 TCP 与电源原值写入 journal，使 `undo` 真正回到执行前；导入 v1 `dns-backup.json` 兼容旧记录。
5. **收尾产品化**：i18n（zh-CN / en）、`watch` 的 rich Live、把 `dev` / `clear` 收敛到 v2，消除双轨状态。
