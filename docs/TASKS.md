# net-optimizer v2 任务拆解

> 配套文档：`docs/SPEC.md`
> 规模标记：S ≈ 半天，M ≈ 1–2 天，L ≈ 3–5 天
> 每个 ticket 的完成定义：代码 + 测试 + 门禁全绿 + 对应缺陷已回归。

---

## 阶段 0：工具链与基线

**目标**：在不改行为的前提下，让 v2 的质量门禁先立起来。

| ID | 任务 | 交付 | 验收 | 规模 |
|---|---|---|---|---|
| T0.1 | 建分支 `rewrite/v2`，main 冻结在 v1.1 | 分支 | main 不再直接提交 | S |
| T0.2 | `pyproject.toml` 补 `[build-system]`、`[project.scripts]`、dependencies、optional-dependencies、dev 组 | 可 `uv sync`、`uv run netopt` | 干净的 venv 能跑 | M |
| T0.3 | mypy 配置（`netopt/` strict，tests 放宽）+ 清零现有 10 处 `type: ignore`（TypedDict 改造 parser） | mypy 通过 | `mypy netopt` 0 error | M |
| T0.4 | `tach.toml` 固化 SPEC §4.2 依赖规则 | 配置文件 | `tach check` 通过；故意加违规 import 会红 | S |
| T0.5 | 重写 `run_tests.py`：ruff → mypy → tach → bandit → pytest-cov | 门禁脚本 | 本地一条命令全绿 | M |
| T0.6 | GitHub Actions：windows-latest + uv + 门禁 + 覆盖率 | workflow | PR 上自动跑 | M |
| T0.7 | 覆盖率门槛 90%，并输出 missing 行 | 配置 | 低于 90 直接失败 | S |
| T0.8 | 建立 `docs/`（SPEC/TASKS/ADR 目录）与 ADR-0001 技术栈决策 | 文档 | 与 SPEC 一致 | S |

**阶段出口**：v1 功能不变，294 个测试仍全绿，CI 生效。

---

## 阶段 1：Report 契约与 status 垂直切片

**目标**：用一条命令跑通 `probe → Report → 三条渲染路径`，验证架构。

| ID | 任务 | 交付 | 验收 | 规模 |
|---|---|---|---|---|
| T1.1 | `domain/report.py`（pydantic）：Report/Section/Metric/Finding/ProbeError/Score | 模型 + 单测 | `model_dump_json` 可序列化；未知字段可忽略 | M |
| T1.2 | `domain/policy.py`：收敛 4 套阈值为一套；默认值与 v1 行为对齐 | 模型 + 单测 | 同一延迟在各命令下分档一致 | M |
| T1.3 | `domain/codes.py`：Finding/ProbeError 常量 | 常量表 | 无散落字符串 | S |
| T1.4 | `render/text.py`：rich 渲染 Report（表格/面板/颜色） | 纯函数 | 快照测试；`--no-color` 生效 | M |
| T1.5 | `render/json.py` + `report.schema.json` 生成 | 序列化 | schema 快照测试 | S |
| T1.6 | `cli.py`（typer）：全局 `--json/--no-color`、退出码规范 | CLI 骨架 | 退出码矩阵测试 | M |
| T1.7 | `commands/status.py`：沿用旧 probes，产出 Report | 命令 | `status`/`--json`/GUI 数据一致 | M |
| T1.8 | GUI 临时适配：status 按钮直接消费 Report | 视图 | 删除该路径的 ANSI 解析 | M |
| T1.9 | `netoptimizer.py` 变兼容壳，转发到 `cli.main()` | 兼容层 | 旧命令全部仍可用 | S |

**阶段出口**：`netopt status --json | jq` 可用；GUI 与 CLI 同源；旧测试全绿。

---

## 阶段 2：系统读取层（ctypes + winreg）

**目标**：读操作不再依赖本地化文本。

| ID | 任务 | 交付 | 验收 | 规模 |
|---|---|---|---|---|
| T2.1 | `system/api.py`：SystemApi Protocol + `SystemUnavailable` + FakeSystemApi | 接口 | 上层可在无 Windows 依赖下测试 | M |
| T2.2 | `GetAdaptersAddresses`：适配器、单播地址、DNS、MTU、oper status | ctypes 模块 | 合成缓冲区单测 + 真机 live 测试 | L |
| T2.3 | `GetIpForwardTable2` + `GetBestRoute2`：默认路由、metric、接口索引 | ctypes 模块 | 与 `route print` 结果比对一致 | L |
| T2.4 | `GetIfTable2`：字节数、错误、丢弃、速率、介质类型 | ctypes 模块 | 真机数值单调递增 | M |
| T2.5 | `registry.py`：`NameServer` / `DhcpNameServer` 判定 static/dhcp，读原值 | 模块 | 与 netsh 结果交叉验证 | M |
| T2.6 | `wlanapi.py`：打开句柄、枚举接口、当前连接（SSID/信号/信道/速率） | ctypes 模块 | 真机（有线时返回未连接） | L |
| T2.7 | `wlanapi.py`：扫描周边网络 | ctypes 模块 | **先验证位置权限**；失败降级 netsh 并记 ProbeError | L |
| T2.8 | `probes` 切换到 SystemApi；netsh 读路径保留为 fallback 一个版本 | 重构 | 关掉 netsh 仍能出完整数据 | L |
| T2.9 | live 测试 marker + 夜间 CI | 测试设施 | 默认跳过，`-m live` 可跑 | M |

**阶段出口**：断网 / 仅 IPv6 / VPN / 无线 四类场景真机结果正确；适配器名含空格中文也正常。

---

## 阶段 3：probes 重构与分析

| ID | 任务 | 交付 | 验收 | 规模 |
|---|---|---|---|---|
| T3.1 | `ProbeContext`：deadline / cancel / 错误收集 | 基础设施 | status 总预算 20s，超时不再穿透 | M |
| T3.2 | 错误分类：timeout/denied/missing/unavailable/parse/network | 枚举 + 映射 | 每个失败都有 code + 人话 | M |
| T3.3 | ping 探测结构化；保留 `ping.exe`（免管理员） | probe | 丢包/抖动计算与 v1 一致 | S |
| T3.4 | DNS 探测：IPv4 + IPv6、UDP→TCP 截断回退 | probe | **修复 IPv6-only 误报** | M |
| T3.5 | HTTP 探测改 httpx，分段 connect/TLS/TTFB/total | probe | 报告四段耗时；失败带原因 | M |
| T3.6 | MTU：预算内二分，超预算 `verified=False` + ProbeError | probe | 最坏耗时 ≤ 8s | M |
| T3.7 | 测速：4 连接并发、取中位数、失败保留原因 | probe | 千兆线路不再被单线程低估 | M |
| T3.8 | `analysis/health.py` 迁移，policy 驱动评分 | 纯函数 | 边界用例与 v1 一致或有意变更并记录 | M |
| T3.9 | `analysis/diagnose.py`：本地/接入/骨干归因 | 纯函数 | 用构造数据覆盖 6 种归因链 | L |
| T3.10 | 其余命令迁移到 Report（full/ping/dns/http/speed/trace/wifi/health/monitor） | 命令 | 旧 render 函数逐条删除 | L |

**阶段出口**：`status` P95 < 8s（不含 MTU 单列），`full` < 60s；所有失败可解释。

---

## 阶段 4：修复与回滚

| ID | 任务 | 交付 | 验收 | 规模 |
|---|---|---|---|---|
| T4.1 | `system/journal.py`：intent→apply→result，JSONL + fsync | 模块 | 中途 kill 进程后可恢复判定 | M |
| T4.2 | `fix dns` 走 journal；导入 v1 `dns-backup.json` | 重构 | 改前可还原；重复执行幂等 | M |
| T4.3 | `fix tcp` 记录原值 + undo 命令 | 重构 | `undo last` 回到原值 | M |
| T4.4 | `fix power` 记录原值 + undo（含注册表） | 重构 | 同上 | M |
| T4.5 | `netopt undo [id|last]`、`fix --dry-run` | 命令 | dry-run 零副作用 | M |
| T4.6 | **修复 `is_primary` 未生效**：只改物理/主接口，虚拟网卡需显式 `--include-virtual` | 修复 | 构造"网关在 vEthernet"用例，默认不触碰 | S |
| T4.7 | 权限错误统一为 exit 3 + 明确提示 | 错误处理 | 非管理员跑 fix 的测试 | S |

**阶段出口**：每种修复都能一键还原；dry-run 可预览。

---

## 阶段 5：GUI 重构

| ID | 任务 | 交付 | 验收 | 规模 |
|---|---|---|---|---|
| T5.1 | 删除 `sys.stdout` 重定向与 ANSI 解析；GUI 只消费 Report | 重构 | 全仓无 `Redirector`/`ANSI_RE` | L |
| T5.2 | 真取消：cancel token 贯穿 probes | 重构 | 长任务可立即停止 | M |
| T5.3 | 结果面板：概览 / 明细表 / 建议 / 原始证据 | 视图 | 与 `--json` 字段一一对应 | L |
| T5.4 | 高 DPI、字体、主题；`tk scaling` 修正 | 视图 | 4K 屏不糊 | M |
| T5.5 | 加载 dev 模式（修 v1 缺陷） | 修复 | dev 下能看到 traceback | S |
| T5.6 | PySide6 评估报告（只评估，不实施） | ADR | 给出结论与成本 | S |

**阶段出口**：GUI 与 CLI 数据一致；无全局 stdout 替换。

---

## 阶段 6：平台化

| ID | 任务 | 交付 | 验收 | 规模 |
|---|---|---|---|---|
| T6.1 | `netopt watch`：采样循环 + `metrics.jsonl` + rich Live | 命令 | 跑 24h 内存稳定 | M |
| T6.2 | `analysis/alerts.py`：规则 + 冷却 + 去重 | 纯函数 | 同一问题不连续轰炸 | M |
| T6.3 | 历史趋势：health 分数、丢包、DNS 延迟 | 查询 + 渲染 | 30 天趋势可读 | M |
| T6.4 | 通知通道选型 + 实现（托盘/Toast） | ADR + 实现 | 告警可见 | M |
| T6.5 | 自启：任务计划程序（不做 Windows 服务） | 安装/卸载 | 重启后自动运行 | M |
| T6.6 | 可选本地 HTTP API + Web 面板（默认关闭） | 命令 | 仅 127.0.0.1，无鉴权也有边界 | L |

**阶段出口**：后台稳定；告警不重复；卸载干净。

---

## 阶段 7：产品化

| ID | 任务 | 交付 | 验收 | 规模 |
|---|---|---|---|---|
| T7.1 | 状态/配置迁 `%LOCALAPPDATA%`，`NETOPT_HOME` + `--portable` | 重构 | 装到 Program Files 也能写 | M |
| T7.2 | 日志改 RotatingFileHandler，禁止裸 except 吞错 | 重构 | 保留 7 天，错误可查 | S |
| T7.3 | PyInstaller 双产物 + 版本信息 + 图标 | 打包 | 干净 Win11 无 Python 可跑 | L |
| T7.4 | 首次运行引导（权限用途、数据不上传） | 交互 | 非技术用户能读懂 | M |
| T7.5 | i18n（gettext，zh-CN/en） | 本地化 | 切语言全界面生效 | L |
| T7.6 | 更新检查（GitHub Releases，仅提示） | 功能 | 无网络时静默 | M |
| T7.7 | README / 发布说明重写（零依赖卖点已变） | 文档 | 与发布形态一致 | S |

**阶段出口**：干净 Windows 双击可用；升级路径清楚。

---

## 并行化建议（工头模式）

接口先冻结：`Report`（T1.1）、`Policy`（T1.2）、`SystemApi`（T2.1）。

| 批次 | 可并行组 | 文件所有权 |
|---|---|---|
| 批次 A | T0.* 工具链 | `pyproject.toml` / `tach.toml` / `.github/` / `run_tests.py` |
| 批次 B | T1.1–T1.3 domain | `netopt/domain/` |
| 批次 C | T1.4–T1.6 render + cli | `netopt/render/` / `netopt/cli.py` |
| 批次 D | T2.2–T2.5 读层 | `netopt/system/iphlpapi.py` / `registry.py` |
| 批次 E | T2.6–T2.7 wlanapi | `netopt/system/wlanapi.py` |
| 批次 F | T3.* probes/analysis | `netopt/probes/` / `netopt/analysis/` |

冲突点：`pyproject.toml`、`run_tests.py`、`netopt/system/api.py` 由单人独占。
每批次结束先跑门禁再合并。

## 关键路径

```
T0.2 → T1.1 → T1.6 → T1.7 → T2.1 → T2.2 → T2.8 → T3.1 → T3.10 → T4.* → T5.* → T7.*
```

估计：单人 8–11 周；三路并行 5–6 周（不含真机验证与返工）。
