# net-optimizer v2 规格

> 状态：待评审
> 日期：2026-10-24
> 基线：v1.1（commit 7b2e468，294 tests / 91% coverage）
> 本文是 v2 重写的唯一契约来源。实现与本文冲突时，先改本文再改代码。

---

## 1. 背景与目标

v1 的核心资产是**领域知识与测试**（真实 fixture、DNS 改前备份、诚实错误提示、三层分层），
不是它的输出方式。v2 要保留前者，替换后者。

四个方向同时推进：

1. **架构重写**：命令返回结构化 `Report`，渲染层独立消费。
2. **功能广度**：更多诊断维度与归因能力。
3. **平台化**：常驻监控、历史趋势、告警。
4. **产品化**：安装包、配置目录、多语言、更新检查。

## 2. 非目标

- 不支持 Linux / macOS。ctypes 直调 Win32 的路线会锁死 Windows，这是明确取舍。
- 不做云服务、不上传任何用户数据。
- 不做代码签名（SmartScreen 警告保留，文档说明）。
- 不在 v2 内重写 GUI 技术栈（tkinter 保留；PySide6 只做评估，不默认引入）。

## 3. 技术栈决策

| 项 | 决策 | 理由 / 被否方案 |
|---|---|---|
| 语言 | Python 3.11+ | 3.10 已进入维护尾期；3.11+ 有 `tomllib`、更快。本机 3.13。 |
| 依赖 | rich / typer / httpx / pydantic / pydantic-settings | 用户选择"全面现代化"。 |
| 包管理 | uv + `uv.lock` | 已安装；锁版本、CI 可复现。 |
| 系统读取 | ctypes → iphlpapi.dll / wlanapi.dll + winreg | 结构化、免本地化、无子进程。被否：netsh 文本（脆弱）、pywin32（重依赖）。 |
| 系统写入 | netsh / powercfg / reg（暂留） | 已验证可用、行为明确；后续可评估 `SetInterfaceDnsSettings`。 |
| 渲染 | rich（终端）+ pydantic JSON + tkinter（GUI） | 三条渲染路径共用 `Report`。 |
| 打包 | PyInstaller（已装） | Nuitka 未装，需另行确认。 |
| 质量 | ruff / mypy / tach / bandit / pytest / coverage / hypothesis | 全部本机已装。 |
| 变异测试 | 不做 | mutmut 官方不支持 Windows（实测报错，需 WSL）。 |

### 3.1 发布形态的硬约束

引入运行时依赖后，**源码运行不再是终端用户的路径**：

- 终端用户：只发 PyInstaller 产物（`NetOptimizer.exe` 无控制台 + `netopt.exe` 控制台）。
- 开发者 / 高级用户：`uv sync` 后 `uv run netopt`。
- `start.bat` 保留，但只作为开发入口；用户文档不再主推。

原因：网络故障时 `pip install` 需要网络，形成死锁。

## 4. 架构总览

```
                 ┌─────────────┐
   CLI (typer) ──┤             │
   GUI (tk)    ──┤  commands/  ├──> Report ──> render/text (rich)
   HTTP API    ──┤             │            └> render/json (pydantic)
                 └──────┬──────┘            └> gui/view
                        │
              ┌─────────┴─────────┐
              │     probes/       │  组合系统数据 + 主动测量
              └────┬─────────┬────┘
                   │         │
            ┌──────┴───┐ ┌───┴──────────┐
            │ analysis/│ │ system/      │
            │ 纯函数    │ │ ctypes/winreg│
            └──────────┘ │ /子进程       │
                         └──────────────┘
```

### 4.1 目录布局

```
netopt/
  domain/
    models.py        # 进程内纯数据（frozen dataclass）
    report.py        # Report / Section / Metric / Finding / ProbeError（pydantic）
    policy.py        # 所有阈值、权重、分档（唯一真值点）
    codes.py         # Finding code / ProbeError code 常量
  system/
    api.py           # SystemApi Protocol + FakeSystemApi
    iphlpapi.py      # GetAdaptersAddresses / GetIpForwardTable2 / GetIfTable2
    wlanapi.py       # WlanEnumInterfaces / WlanQueryInterface / 扫描
    registry.py      # winreg：DNS 原值、static/dhcp 判定
    commands.py      # netsh / powercfg / reg / ping / tracert 子进程
    journal.py       # 变更日志 + undo
    elevate.py
  probes/
    context.py       # ProbeContext：deadline / cancel / 错误收集
    connectivity.py  # ping / tcp connect
    dns.py           # UDP+TCP 查询，IPv4/IPv6
    http.py          # httpx：connect/TLS/TTFB 分段计时
    mtu.py
    speed.py         # 多连接下载 / 上传
    adapters.py
    wifi.py
  analysis/
    health.py        # 评分（纯函数，policy 驱动）
    diagnose.py      # 归因：本地 / 接入 / 骨干
    alerts.py        # 告警规则与去抖
  render/
    text.py          # rich
    json.py
  commands/
    status.py  full.py  ping.py  dns.py  http.py  speed.py
    trace.py   wifi.py  fix.py   monitor.py  health.py  watch.py
  config.py          # pydantic-settings，TOML
  state.py           # 历史 / 日志 / 原始输出
  cli.py             # typer
  gui/
    app.py  view.py
netoptimizer.py      # 兼容壳：解析旧参数 → 转发 cli.main()
```

### 4.2 依赖规则（tach 强制）

| 模块 | 允许依赖 |
|---|---|
| `domain` | 无（仅标准库 + pydantic） |
| `system` | `domain` |
| `probes` | `domain`, `system` |
| `analysis` | `domain` |
| `render` | `domain` |
| `commands` | `domain`, `probes`, `analysis`, `system`（仅 journal/elevate） |
| `cli` | `commands`, `render`, `config` |
| `gui` | `commands`, `render`, `domain`, `config` |
| `state` / `config` | `domain` |

铁律：`render` 不得 import `probes`/`system`；`analysis` 不得碰 IO。

## 5. 核心契约

### 5.1 Report

```python
class Severity(StrEnum):
    ok = "ok"
    info = "info"
    warn = "warn"
    critical = "critical"


class ProbeError(BaseModel):
    code: str  # timeout | denied | missing | unavailable | parse | network
    source: str  # "iphlpapi" | "ping" | "dns:223.5.5.5" ...
    message: str
    retryable: bool = False


class Metric(BaseModel):
    key: str
    label: str
    value: float | None
    unit: str = ""
    good: float | None = None  # 来自 policy
    warn: float | None = None
    available: bool = True
    note: str | None = None


class Evidence(BaseModel):
    source: str
    detail: str | None = None
    raw_ref: str | None = None  # 原始输出另存文件，不塞 Report


class Finding(BaseModel):
    code: str
    severity: Severity
    title: str
    detail: str
    advice: list[str] = []
    evidence: list[Evidence] = []


class Section(BaseModel):
    id: str
    title: str
    metrics: list[Metric] = []
    rows: list[dict[str, Any]] = []
    findings: list[Finding] = []


class Score(BaseModel):
    total: int
    grade: str
    items: list[dict[str, Any]]


class Report(BaseModel):
    schema_version: int = 1
    command: str
    started_at: datetime
    duration_ms: int
    environment: dict[str, Any]  # os build / admin / locale / python
    sections: list[Section]
    findings: list[Finding]
    errors: list[ProbeError]
    score: Score | None = None
```

规则：

- `Report` 是**唯一**跨命令/跨前端的数据结构。
- 原始命令输出不进 JSON，写 `raw/<run_id>/`，Report 只留 `raw_ref`。
- `schema_version` 只增不改；破坏性字段变更必须升版本，消费方忽略未知字段。
- 所有缺失值用 `None` + `available=False` 表达，禁止用 `-1`/`0` 冒充。

### 5.2 阈值（policy 唯一真值点）

现状有 4 套互相矛盾的"外网延迟"标准（30/100、30/150、>80），全部收敛到：

```python
class Policy(BaseModel):
    gateway: Band = Band(good=5, warn=30, poor=50)
    wan: Band = Band(good=30, warn=100, poor=150)
    dns: Band = Band(good=30, warn=100, poor=200)
    http_ttfb: Band = Band(good=150, warn=500, poor=1000)
    loss: LossPolicy = LossPolicy(tolerate=2, unusable=50)
    mtu: MtuPolicy = MtuPolicy(standard=1500, pppoe=1492, low=1400)
    weights: dict[str, int] = {...}
```

`render` 只读 `Metric.good/warn`，不得自带阈值。

## 6. 系统访问层

### 6.1 SystemApi（Protocol）

```python
class SystemApi(Protocol):
    def adapters(self) -> list[Adapter]: ...
    def addresses(self) -> list[Address]: ...
    def dns_servers(self) -> list[InterfaceDns]: ...
    def routes(self) -> list[Route]: ...
    def if_stats(self) -> list[InterfaceStats]: ...
    def wifi(self) -> WifiState: ...
    def wifi_scan(self) -> WifiScan: ...
    def platform_info(self) -> PlatformInfo: ...
```

- `LiveSystemApi`：ctypes + winreg 实现。
- `FakeSystemApi`：测试用，构造任意系统状态。
- 任何 DLL 缺失 / 调用失败 → 抛 `SystemUnavailable`，由 probe 转成 `ProbeError`，**不得静默返回空列表**（v1 的 `if res.missing: return []` 会伪装成"没有网卡"）。

### 6.2 ctypes 范围

| 数据 | API |
|---|---|
| 适配器、地址、DNS、MTU | `GetAdaptersAddresses`（AF_UNSPEC, INCLUDE_PREFIX/INCLUDE_GATEWAYS） |
| 默认路由、metric | `GetIpForwardTable2` + `GetBestRoute2` |
| 接口计数、错误、丢弃、速率 | `GetIfTable2`（MIB_IF_ROW2） |
| 全局 IP 统计 | `GetIpStatisticsEx` |
| WiFi 状态 | wlanapi.dll：`WlanOpenHandle` / `WlanEnumInterfaces` / `WlanQueryInterface` |
| WiFi 周边扫描 | wlanapi.dll：`WlanScan` + `WlanGetAvailableNetworkList` |
| DNS 静态/DHCP 判定 | `winreg`：`Tcpip\Parameters\Interfaces\{GUID}` 的 `NameServer` / `DhcpNameServer` |

风险：Win11 的周边 WiFi 扫描可能同样受"位置权限"限制（v1 的 D16）。
E5 必须先做真机验证；失败时降级 `netsh wlan show networks`，并把原因写进 Report。

### 6.3 写入

v2 阶段保留 v1 的写入命令（netsh / powercfg / reg），已验证可靠。
所有写入必须先写 journal 的 intent 记录，再执行。

## 7. 探测层

### 7.1 ProbeContext

```python
class ProbeContext:
    deadline: float  # 总预算，秒
    cancel: threading.Event
    errors: list[ProbeError]

    def remaining(self) -> float: ...
    def guard(self, name: str) -> ContextManager: ...
    def record_error(self, err: ProbeError) -> None: ...
```

- 每个 probe 必须有超时；超时记 `ProbeError(code="timeout")`，不抛异常穿透。
- `status` 总预算默认 20s（MTU 单列 8s），`full` 默认 120s。可配置。
- MTU 探测最坏 40 次 ping 的问题必须消除：改为预算内探测，超预算返回 `verified=False` + `ProbeError`。

### 7.2 错误必须可解释

v1 的 `except Exception: return None` 是反模式。v2 每个失败至少保留：
`code` + `source` + 一句人话。展示层负责把 code 翻译成建议。

### 7.3 测量语义

| 指标 | 定义 |
|---|---|
| ping | ICMP echo，4 包，丢包率 = (发出-收到)/发出 |
| DNS | UDP 优先，TC 截断时回落 TCP；IPv6 服务器用 AF_INET6 |
| HTTP | httpx trace 分段：connect / tls / ttfb / total |
| 下载 | 4 条并发连接，取中位数；单连接结果仅作参考 |
| 上传 | 同上下载；失败保留原因 |
| MTU | DF 二分 + 边界确认；无法确认时 `verified=False` |

## 8. 分析与评分

- `analysis/health.py`：纯函数，输入 domain 数据 + Policy，输出 `Score`。
- `analysis/diagnose.py`：归因链
  `网关丢包 → 接入网问题（WiFi/网线/路由器）`
  `网关正常 + 外网丢包 → 运营商/骨干`
  `外网正常 + DNS 慢 → DNS 选型`
  `全正常 + TCP 重传高 → 线路质量/驱动`
- 所有建议必须由 `Finding.code` 驱动，禁止在渲染层写业务判断。

## 9. 渲染

### 9.1 text（rich）

- 表格、面板、进度条、`Live` 刷新（替代 `\r` 手搓）。
- 颜色语义统一：`ok=green / info=cyan / warn=yellow / critical=red`。
- `--no-color` 与 `NO_COLOR` 环境变量尊重。

### 9.2 json

- `report.model_dump_json()`，UTF-8，缩进可选。
- stdout 只有 JSON；日志/进度进 stderr。
- 附 `schema_version`，并生成 `report.schema.json` 做契约测试。

### 9.3 gui

- 只接收 `Report`，构建表格 + 详情 + 建议面板。
- 删除 `sys.stdout` 重定向、ANSI 正则、`\r` 特殊处理。
- 长任务通过 `cancel` token 真正取消。

## 10. CLI 契约

```
netopt status [--json] [--timeout 20]
netopt full [--json]
netopt ping [TARGET] [-n 4] [--json]
netopt dns [--servers 223.5.5.5,...] [--json]
netopt http [--json]
netopt speed [--download-only|--upload-only] [--json]
netopt trace [TARGET] [-h 20]
netopt wifi [--scan] [--json]
netopt health [--json]
netopt monitor [-n 60] [--interval 1] [--json]
netopt watch [--interval 5] [--out PATH]
netopt fix [dns|tcp|power|all] [--restore] [--dry-run] [--json]
netopt undo [ID|last]
netopt dev on|off
netopt config get|set|edit
netopt version | help
```

退出码：

| code | 含义 |
|---|---|
| 0 | 完成，无 critical finding |
| 1 | 用法错误 |
| 2 | 完成，但有 critical finding（可用 `--fail-on warn` 放宽） |
| 3 | 需要管理员权限 |
| 4 | 内部错误 |

`--json` 时退出码语义不变；错误对象也进 Report.errors。

## 11. 修复与回滚

```python
class Change(BaseModel):
    id: str  # ulid/时间戳
    ts: datetime
    kind: Literal["dns", "tcp", "power", "registry"]
    target: str
    before: dict[str, Any]
    after: dict[str, Any]
    undo: list[list[str]]  # 可直接执行的 argv
    applied: bool
    result: str | None
```

流程：

1. 读当前值 → 2. 写 `intent` 记录（fsync）→ 3. 执行 → 4. 写 `result`。
2. 任一步失败，`netopt undo last` 必须能回到执行前。
3. `fix --dry-run` 只打印计划，不落盘、不执行。
4. v1 的 `dns-backup.json` 保留只读兼容（首次运行导入 journal）。

## 12. 状态与配置

```
%LOCALAPPDATA%\net-optimizer\
  config.toml
  state\history.jsonl
  state\changes.jsonl
  logs\netopt-YYYYMMDD.log      # 保留 7 天
  raw\<run_id>\...
  cache\
```

- `NETOPT_HOME` 覆盖根目录（测试与便携模式用）。
- `--portable` 使用程序目录（保留 v1 行为）。
- 日志用标准 `logging` + RotatingFileHandler，禁止裸 `except: pass` 吞错
  （v1 的 `state.log` 吞掉所有异常，排查时无从下手）。
- 历史 JSONL 按行追加，读取时容忍坏行。

## 13. 平台化

阶段 6 范围，先做最小闭环：

1. `netopt watch`：前台采样，写 `metrics.jsonl`，rich Live 展示。
2. 告警规则：`Finding.code` + 阈值 + 冷却时间，避免重复轰炸。
3. 自启：任务计划程序（`schtasks`），**不做 Windows 服务**（需额外依赖与权限）。
4. 通知通道：托盘气泡或 Toast，选型待阶段 6 开始前确认。
5. 可选：本地 HTTP API + 简单 Web 面板（FastAPI/uvicorn），默认关闭。

## 14. 产品化

- PyInstaller 双产物；版本号单一来源 `importlib.metadata.version("net-optimizer")`。
- 首次运行引导：说明管理员权限用途、数据不上传。
- i18n：gettext，首批 zh-CN / en（解析层已不依赖语言，只翻 UI 文案）。
- 更新检查：GitHub Releases API（httpx），只提示不自动安装。
- README 重写：零依赖卖点移除，改为"免安装 exe + 可审计源码"。

## 15. 测试策略

| 层 | 方式 |
|---|---|
| domain / analysis / render | 纯函数单测，构造数据 |
| system/ctypes | 合成字节缓冲区测结构解析；`FakeSystemApi` 测上层 |
| probes | fake SystemApi + 注入时钟；不真实执行写操作 |
| 命令层 | Report 快照测试 + JSON schema 快照 |
| 真机 | `@pytest.mark.live`，默认跳过，夜间 CI 跑 |
| 属性测试 | hypothesis：policy 单调性、parser 不崩 |
| 回归 | v1 的 294 个测试保留，直到对应模块删除 |

门禁（`uv run python run_tests.py`）：

1. `ruff check` + `ruff format --check`
2. `mypy netopt`
3. `tach check`
4. `bandit -r netopt/system`
5. `pytest --cov=netopt --cov-fail-under=90`
6. import 冒烟

CI：GitHub Actions `windows-latest`，uv 缓存，夜间加 `-m live`。

## 16. 迁移策略

采用绞杀者模式，不一次性重写：

| 阶段 | 内容 | 旧模块状态 |
|---|---|---|
| P0 | 工具链 + CI + 分支 | 全保留 |
| P1 | Report + status 垂直切片 | 旧 cmd_status 下线 |
| P2 | system 读取层 + probes 接入 | netsh 读路径降级为 fallback |
| P3 | 其余命令迁移 + analysis | 旧 render 函数逐条删除 |
| P4 | fix + journal | `dns-backup.json` 转只读 |
| P5 | GUI 重构 | 删除 stdout 重定向 |
| P6 | 平台化 | — |
| P7 | 产品化 | `netoptimizer.py` 变兼容壳 |

每个阶段结束必须：门禁全绿、旧测试仍过、`--json` schema 不变。

## 17. v1 缺陷 → 修复工单

| 缺陷 | 工单 |
|---|---|
| `is_primary` 未生效，`fix dns` 可能改虚拟网卡 | T4.6 |
| `cmd_status` 不筛 IPv6 DNS，误报解析失败 | T3.4 |
| MTU 探测无总预算，status 可能卡 40s | T3.1 / T3.6 |
| 退出码永远 0 | T1.6 |
| `clear` 后立刻重建日志 | T7.2 |
| GUI 不加载 dev 模式 | T5.5 |
| `http_ttfb` 少算 TCP+TLS | T3.5 |
| 失败原因被吞成 None | T3.2 |
| 阈值四套并存 | T1.2 |
| `type: ignore` 10 处 | T0.3 |
| 状态写在程序目录 | T7.1 |
| TCP/电源修复不可回滚 | T4.3 / T4.4 |

## 18. 风险与开放问题

1. **wlanapi 扫描权限**：Win11 可能仍要求位置权限，需 E5 真机验证。
2. **ctypes 结构体**：32/64 位对齐必须测；Windows 版本差异（Win10 1809 以下）需明确下限。
3. **发布形态切换**：老用户习惯 `start.bat`，升级需说明。
4. **依赖体积**：PyInstaller + rich/pydantic 产物预计 30–50MB，需实测。
5. **平台化通知通道**：未定（托盘 / Toast / Webhook）。
6. **Python 下限**：本文取 3.11，若需兼容 3.10 请提出。
7. **GUI 终态**：Phase 5 再决定是否上 PySide6。

## 19. 待确认的假设

以下假设已按合理默认写入本文，若不同意请直接指出：

- A1：发布以打包 exe 为主，源码安装只面向开发者。
- A2：v2 只支持 Windows 10 1809+ / Windows 11。
- A3：阶段 6 的通知通道先做托盘气泡，不做 Webhook。
- A4：旧命令字面量全部保留（`status/full/auto/...`），`auto` 作为 `fix all --diagnose` 的别名。
