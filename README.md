# net-optimizer — Windows 网络诊断与一键优化工具

针对"网络动不动卡"编写的网络工具，无需安装任何第三方依赖（纯 Python 标准库，要求 Python 3.10+）。

## 使用方法（推荐）

**双击 `start.bat`** 即可打开图形界面，所有功能都是按钮，点一下就执行。
双击时会默认**以管理员身份启动**（弹 UAC 点"是"即可），这样修复功能
直接在本窗口执行，无需跳来跳去；若取消 UAC 则以普通模式启动，
点修复按钮时会再弹 UAC 到新窗口执行。
卡顿时先点「快速诊断」定位问题，再点「一键优化 auto」自动修复。
（建议把 start.bat 发送到桌面或固定到任务栏）

> 想强制普通模式启动：`set NOELEVATE=1` 后再双击，或在窗口里点「以管理员重启」随时升级。
>
> 启动器会自动寻找 Python（`py` 启动器 → `pythonw.exe` → `python.exe`）；
> 一个都找不到时会给出明确提示，而不是窗口一闪就没。

## 命令行用法（进阶）

```bat
python netoptimizer.py <命令> [参数]
```

## 命令一览

| 命令 | 功能 |
| :--- | :--- |
| `status` | 快速诊断（Ping+DNS+HTTP+MTU） |
| `full` | 全面诊断（含带宽/路由/WiFi） |
| `auto` | 一键优化（诊断→自动修复全部，需管理员） |
| `ping [目标]` | 延迟测试（默认百度） |
| `dns` | DNS 解析基准（7 个服务器） |
| `http` | HTTP 延迟测试（4 个站点） |
| `speed` | 带宽测速（下载+上传） |
| `trace [目标]` | 路由追踪（默认百度） |
| `wifi` | WiFi 信号/信道/频段 |
| `fix dns/tcp/power` | 自动修复（需管理员，见下节） |
| `fix dns --restore` | **还原 DNS**：把 DNS 还原成 `fix dns` 修改前的原值（需管理员） |
| `monitor [次数]` | 百度延迟采样（默认 60 次） |
| `dev on/off` | 开发者模式（需管理员，回显原始命令） |
| `health` | 健康评分+优化建议 |
| `admin` | 以管理员身份重启本程序 |
| `clear` | 清除日志/历史和 dev 标志（**保留 `dns-backup.json`**） |
| `help` | 显示帮助 |

## 日常使用建议

- **卡顿时**：先 `status` 看是哪一环的问题，再跑 `auto` 一键优化（自动修复 DNS/TCP/电源节能并复测对比）。
- **每周**：跑一次 `health` 查看健康评分趋势。
- **WiFi 卡**：`wifi` 查看信号强度和信道拥堵情况，判断是否该换信道或改用 5GHz。
- **改过 DNS 想恢复**：`fix dns --restore`（或 GUI 里的「还原 DNS」按钮）。

## 自动修复内容

- `fix dns`：**只动承载默认路由的那张网卡**（不会碰 VPN/虚拟网卡，避免打断内网
  split-DNS），修改前先把原 DNS 配置备份到 `dns-backup.json`，然后清 DNS 缓存并把
  DNS 设为 阿里 223.5.5.5 / 腾讯 119.29.29.29。备份失败就中止，绝不无备份地改。
- `fix dns --restore`：按 `dns-backup.json` 把 DNS **还原成修改前的原值**
  （静态 DNS 原样还原，动态(DHCP)的还原为自动获取）。没有备份会明确提示。
- `fix tcp`：TCP 自动调优恢复正常、禁用 ECN、开启 RSS、关闭非对称延迟容忍
- `fix power`：禁用无线网卡节能（解决省电导致的掉线卡顿）+ 禁用 USB 选择性暂停

## 文件说明

入口是薄壳，核心逻辑都在 `netopt/` 包（旧的扁平模块 `netlib.py` / `diag.py` /
`fix.py` / `health.py` 已由它取代）：

- `start.bat` — **双击启动图形界面（主入口）**
- `gui.py` — 图形界面（tkinter 按钮界面，只管按钮/输出重定向）
- `netoptimizer.py` — 命令行入口（命令分发、管理员提权）
- `netopt/` — 核心包：
  - `models.py` — 纯 dataclass 领域数据，无 IO
  - `parsers.py` — 纯函数，命令输出文本 → 领域数据（解析唯一真值点）
  - `platform.py` — 系统边界：执行命令、管理员判定/提权、控制台初始化
  - `probes.py` — 组合 platform + parsers，产出领域数据（ping/DNS/MTU/WiFi…）
  - `state.py` — 日志 / 历史 / dev 标志 / DNS 备份路径
  - `ui.py` — 渲染原语（颜色/进度条/中文对齐）
  - `diag.py` / `fix.py` / `health.py` — 编排层：探测 → 渲染 → 打印
- `run_tests.py` — 本地门禁（import 冒烟 + ruff + pytest）
- `log-*.log` — 运行日志（自动按天生成）
- `history.json` — 诊断历史（供 health 趋势对比）
- `dns-backup.json` — `fix dns` 改前的 DNS 备份，供 `fix dns --restore` 还原

> `clear` 会删除日志、`history.json` 和 `dev.json`，但**不动 `dns-backup.json`**——
> 那是还原 DNS 的唯一依据。

## 开发与测试

```bat
python run_tests.py          :: 全量门禁：import 冒烟 / ruff check / ruff format / pytest
python run_tests.py --fast   :: 跳过 ruff，只跑冒烟和测试
python -m pytest tests -q    :: 只跑单元测试
```

> 本机是 cp936 locale，跑 pytest 前如遇启动报错，请带 `PYTHONUTF8=1`：
> `set PYTHONUTF8=1` 后再运行（`run_tests.py` 已自动为子进程设置）。

新代码按**三层结构**组织，便于维护和单测：

1. **parsers（纯函数）**：`str -> models`，所有文本解析的唯一真值点，
   用 `tests/fixtures/` 里的真实命令输出样本直接测，不碰系统。
2. **probes（探测层）**：组合 `platform` + `parsers` 产出领域数据。
   凡是要执行命令的函数都接受可注入的 `run` 参数（默认在调用时解析为
   `platform.run`），测试注入假 runner，**绝不真实执行会改系统的命令**。
3. **render（渲染层）**：纯函数，数据 → 文本行/字符串，只拼字符串不打印；
   `cmd_*` 负责把三层串起来。

加新命令时按这个结构走：解析逻辑进 `parsers.py` 并补单测 → 探测进 `probes.py`
→ 展示进 `render_*` 纯函数 → 最后在 `cmd_*` 里编排。
