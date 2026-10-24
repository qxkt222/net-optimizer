# net-optimizer

Windows 网络诊断与一键优化工具。v2 重写版，界面中文，只支持 Windows 10 1809+ / Windows 11。

> 当前状态：v2 开发中。`netopt.exe` 与 `NetOptimizer.exe` 已实际构建并完成命令行冒烟；
> 构建产物不随仓库提交。实现进度与已知限制见 [`docs/STATUS.md`](docs/STATUS.md)。

## 终端用户

发布形态是免安装的单文件 exe（由 `packaging/` 下的 spec 定义）：

- `NetOptimizer.exe`：图形界面，双击运行。
- `netopt.exe`：命令行版本，在终端里运行。

程序不需要安装 Python 或任何第三方依赖。放到任意目录即可。
当前构建产物：`netopt.exe` 约 16.0 MB，`NetOptimizer.exe` 约 19.1 MB。

### 管理员权限

- 只读诊断（`status`、`health`、`ping`、`dns`、`http`、`speed`、`trace`、`wifi`、`full`、`watch`、`monitor`、`update`、`config`、`version`）**不需要**管理员权限。
- `fix`、`undo` 与 `auto` 会修改系统设置，必须以管理员身份运行。非管理员执行时返回退出码 3，且**不做任何修改**；`fix --dry-run` 只生成计划，不需要管理员。
- GUI 在普通用户下点修复按钮时会请求 UAC，提权到新控制台窗口执行。

### 数据与隐私

- **不上传任何诊断数据**。没有遥测，没有云端接口。
- 探测会访问命令中列出的目标：默认网关、`www.baidu.com`、4 个常用站点、7 个公共 DNS（阿里 / 腾讯 / 114 / Google / Cloudflare / 百度 / OpenDNS）。
- 结果保存在本机：v2 的健康历史与变更日志在 `%LOCALAPPDATA%\net-optimizer\state\`。
  旧入口（`netoptimizer.py`）的日志与 `history.json` 仍写在程序目录，这是 v1 行为。

### SmartScreen

exe 未做代码签名，首次运行 Windows 会显示「Windows 已保护你的电脑」。这是未签名程序的预期行为：
点「更多信息」→「仍要运行」。校验下载来源请以发布页给出的 SHA-256 为准。

## 命令行

```bat
netopt.exe --help
netopt.exe status
netopt.exe --json status
```

### 命令表

| 命令 | 说明 |
| :--- | :--- |
| `status` | 快速诊断：网关 / 外网 / DNS / HTTP / MTU |
| `health` | 健康评分：五项加权，输出 0–100 总分与 优 / 良 / 中 / 差 |
| `ping [TARGET]` | 网关 + 目标主机的 ping 延迟与丢包，默认 `www.baidu.com` |
| `dns` | 7 个公共 DNS + 当前系统 DNS 的解析耗时对比 |
| `http` | 4 个常用站点的 HTTPS 首字节耗时 |
| `speed` | 多连接并发下载 + 上传吞吐 |
| `trace [TARGET]` | 按跳展示 tracert 原始输出，默认 `www.baidu.com` |
| `wifi` | 当前连接、信号强度与信道占用 |
| `full` | status + speed + trace + wifi 合成一份报告 |
| `watch` | 常驻采样：每轮 status → 告警去抖 → 追加 `metrics.jsonl`，逐轮打印一行；`--interval` / `--count` / `--out` |
| `monitor` | 持续采样：等价于 `watch --interval 1 --count 60`（文本输出，`-n` 指定轮数） |
| `auto` | 一键优化：诊断 → 自动修复全部 → 复测（需管理员）；`--dry-run` 只出修复计划 |
| `fix [dns\|tcp\|power\|all]` | 执行修复，默认 `all`；`--dry-run` 只出计划；`--restore` 还原 DNS |
| `undo [ID\|last]` | 回滚最近一次或指定 ID 的修复 |
| `update` | 检查是否有新版本（只读查询 GitHub Releases）；`--strict` 让检查失败返回 2 |
| `version` | 打印版本号 |
| `config get` | 读取当前配置（含环境变量覆盖）；`--json` 输出 JSON |
| `config set KEY VALUE` | 修改一个配置项，支持点号键（如 `policy.wan.warn`、`language`）；非法键/值退出 1 |
| `config path` | 打印实际配置文件路径（`config.toml`） |

全局选项：

- `--json`：输出结构化 JSON。**前置（`netopt --json status`）与后置（`netopt status --json`）等价**，
  两者同时出现也取 OR。`status` / `health` / `ping` / `dns` / `http` / `speed` / `trace` /
  `wifi` / `full` / `auto` / `watch` / `fix` / `undo` 都接受后置写法；`config get` 与
  `update` 同样支持。`watch --json` 必须同时指定 `--count`，否则退出码 1（常驻采样无法
  在结束时一次性输出 JSON）。
- `--no-color`：禁用彩色输出（等价于 `NO_COLOR=1`）。
- `--portable`：便携模式，把运行期目录（配置 / 状态 / 日志）放到程序根目录，
  等价于把 `NETOPT_HOME` 设为程序所在目录；必须在命令执行前生效。

`--json` 时 stdout **只有** JSON，提示与错误一律走 stderr。`watch` / `monitor` 的文本模式
每轮立即打印一行（时间 / 分数 / 告警数），常驻采样不会累积历史样本。

### 退出码

| 退出码 | 含义 |
| :--- | :--- |
| 0 | 完成，无 critical finding |
| 1 | 用法错误（未知命令 / 未知参数 / 中断） |
| 2 | 完成但有 critical finding；`fix` / `undo` 有失败步骤、`update --strict` 检查失败时同样返回 2 |
| 3 | 需要管理员权限（未执行任何修改） |
| 4 | 内部错误 |

### 修复与回滚

- **DNS**：只改承载默认路由的主接口，不碰 VPN / 虚拟网卡；改前先把原值（服务器列表 + static/dhcp 来源）写入变更日志，再执行。`netopt undo last` 按日志回滚：静态 DNS 还原为原服务器，DHCP 还原为自动获取。读不到原值时会在结果里明确提示，并按 DHCP 处理。
- **TCP**：`netsh int tcp show global` 的原始文本会记录，但**原值解析未实现**，undo 列表为空，**不能自动回滚**，需要人工对照执行前输出恢复。
- **电源**：原值同样只记录原始文本、未解析；undo 命令只会把无线网卡节能与 USB 选择性暂停**恢复为内置默认值**，不保证等于执行前的机器状态。因此它不是严格意义的真回滚。
- `fix dns --restore` 等价于 `undo last`，且只针对 DNS。
- `auto` 复用同一套修复流程（诊断 → `fix all` → 复测），每一步同样先写 journal。
- `fix --dry-run` 只生成计划：不执行任何写命令、不写变更日志。DNS 计划仍会只读当前接口配置，以便确定目标网卡。

### 旧入口兼容

`netoptimizer.py` 保留 v1 的命令字面量：`status` / `health` / `ping` / `dns` / `http` /
`speed` / `trace` / `wifi` / `full` / `fix` / `undo` / `watch` / `monitor` / `auto`
统一转交 v2 CLI，参数、`Report` 与退出码和 `netopt` 一致。只有下面这些仍由旧实现处理，
输出纯文本：

| 命令 | 说明 |
| :--- | :--- |
| `python netoptimizer.py dev on\|off` | 开发者模式，回显原始命令 |
| `python netoptimizer.py clear` | 清除日志 / 历史 / dev 标志（保留 `dns-backup.json`） |
| `python netoptimizer.py admin` | 以管理员身份重启 |
| `python netoptimizer.py help` | 帮助 |

> 旧入口的 `auto` 现在也走 v2，修复记录写入 journal，不再写 v1 的 `dns-backup.json`。

## 开发者

要求：Windows、Python 3.11+、[uv](https://docs.astral.sh/uv/)。

```bash
uv sync --all-groups                 # 安装运行时依赖 + 开发依赖（pytest / ruff / mypy / pyinstaller…）
uv run python run_tests.py           # 本地门禁：ruff → format → mypy → tach → bandit → pytest-cov（≥90%）
uv run python run_tests.py --fast    # 跳过静态检查，只跑 import 冒烟 + pytest
uv run python -m netopt --help       # 源码方式运行 CLI
uv run netopt --help                 # 通过 pyproject 的 console script 运行
```

已激活虚拟环境时也可直接 `python -m netopt ...`。本机是 cp936 控制台；直接跑 pytest 遇到编码报错时加
`PYTHONUTF8=1`（`run_tests.py` 已为子进程设置）。Python 3.13 上跑覆盖率需 `COVERAGE_CORE=ctrace`，
否则 coverage 的 sysmon 核心可能与多线程组合导致进程崩溃（`run_tests.py` 已内置）。

### 打包

```bash
pyinstaller packaging/netopt.spec       # dist/netopt.exe（有控制台）
pyinstaller packaging/netopt-gui.spec   # dist/NetOptimizer.exe（无控制台）
```

两份 spec 都是 onefile。仓库不提交 `dist/` 与 `build/`；当前构建产物与冒烟记录见 `docs/STATUS.md`。

### 目录结构

```text
netopt/
  domain/       纯契约：Report / Section / Metric / Finding / Policy / codes / Change
  system/       系统边界：SystemApi + FakeSystemApi、iphlpapi、wlanapi、registry、
                netsh/powercfg/reg 子进程、journal、LiveSystemApi
  probes.py     探测基础：ping / 接口 / 网关 / DNS 配置 / MTU / ProbeContext
  probes_dns.py DNS 探测：IPv4/IPv6、UDP 截断回落 TCP
  probes_http.py HTTP 分段计时：connect / TLS / TTFB / total
  probes_mtu.py 预算内 DF 二分 + 边界确认
  probes_speed.py 多连接并发吞吐
  analysis/     纯函数：健康评分、归因、告警去抖
  render/       Report → rich 文本 / JSON / 无 ANSI 纯文本
  commands/     编排层：探测 → Report；fix / undo 产出计划与结果（不打印）
  cli.py        typer 入口：参数解析、渲染、退出码
  __main__.py   python -m netopt 入口
  config.py     config.toml 读写与环境变量覆盖
  update.py     GitHub Releases 版本检查
  paths.py      运行期目录（%LOCALAPPDATA% / NETOPT_HOME / --portable）
  history.py    JSONL 追加与读取
  state.py      v1 状态文件（日志 / history.json / dev 标志 / dns-backup.json）
gui.py          tkinter 图形界面（消费 Report，不再重定向 stdout）
netoptimizer.py v1 命令兼容壳
packaging/     PyInstaller spec（netopt.exe / NetOptimizer.exe）
tests/         单元测试与真实命令输出样本
docs/          SPEC / TASKS / STATUS / ADR
```

### 测试策略

- **假 runner**：`tests/conftest.py` 的 autouse 夹具拦截 `netopt.platform.run`。任何忘记注入假 runner 的测试会立刻失败，绝不会真的执行 `netsh set` / `powercfg /set*` / `reg add` / `ipconfig /flushdns`。不要绕过它去 patch `subprocess`。
- **FakeSystemApi**：`netopt/system/api.py` 提供可构造任意系统快照的测试替身；上层命令与探测都通过 `SystemApi` 注入。
- **合成缓冲区**：`iphlpapi` / `wlanapi` 的结构体解析用合成的 ctypes 缓冲区单测，不依赖真机。
- **真实样本**：`tests/fixtures/` 保存脱敏后的真实命令输出，解析器以其为唯一真值输入。
- **属性测试**：hypothesis 覆盖 policy 单调性与解析器不崩溃。
- **live 测试待补**：`tests/test_system_live.py` 目前只检查导入与协议兼容，没有真机标记，也没有接入 CI。

当前规模：1098 passed / 1 skipped，覆盖率 93.08%；`run_tests.py` 全门禁 7/7（2026-10-24 快照）。

## 已知限制

- **本机没有无线网卡**：WiFi「已连接」与扫描路径只有合成测试，未在真机验证。
- **GUI 交互未人工验证**：`NetOptimizer.exe` 已构建，但按钮流程、高 DPI、提权与取消只经过源码级测试。
- **无代码签名**：SmartScreen 会拦截，见上文。
- **未做 i18n**：界面与输出只有中文。
- **TCP / 电源不能真回滚**：原值未解析，详见「修复与回滚」。
- **`dev` / `clear` / `admin` 仍只在旧入口**：其余命令（含 `watch` / `monitor` / `auto`）已转交 v2 CLI。
- **`watch` 未用 rich Live**：当前逐轮打印文本并实时输出，没有常驻刷新面板。
- **更新检查暂时 404**：仓库尚无 Release，`update` 返回 `error` 字段并降级为“无可用更新”，不影响其他功能。
- **CLI 参数面小于规格**：`status` 没有 `--timeout`，`ping` 没有 `-n`，`dns` 没有 `--servers`，`wifi` 没有 `--scan`。

## 许可证

[MIT](LICENSE)
