# 0001 技术栈与分发形态

- 状态：Accepted
- 日期：2026-10-24
- 关联：`docs/SPEC.md` §3；`docs/TASKS.md` T0.2

## 背景

v1 是纯标准库、源码直接运行的 Windows 网络诊断工具。v2 要在保留 v1 行为契约
（Report 结构、阈值、CLI 输出）的前提下重写为可维护、可测试、可分发的产品。

## 决策

| 项 | 决策 |
|---|---|
| 语言 | Python 3.11+（本机 3.13） |
| 运行时依赖 | rich、typer、httpx、pydantic、pydantic-settings |
| 包管理 | uv + `uv.lock`，本地与 CI 共用同一份锁 |
| 系统读取 | ctypes 直调 `iphlpapi.dll` / `wlanapi.dll`，配置读 `winreg` |
| 系统写入 | 保留 netsh / powercfg / reg |
| 分发 | PyInstaller 打包 |

### 被否方案与理由

- **语言：继续 3.10** —— 已进入维护尾期，且缺 `tomllib` 等便利特性；**固定 3.13**
  —— 把贡献者与 CI 绑死在单个小版本上，收益不足。
- **包管理：pip + requirements.txt** —— 无解析锁，本地与 CI 可能装出不同版本；
  **Poetry** —— 多一层配置与更慢的解析，本机已有 uv。
- **依赖：坚持零第三方依赖** —— 参数解析、终端渲染、HTTP 分阶段超时都要自维护，
  成本高于收益；**click 代替 typer** —— typer 基于 click 且直接吃类型注解，样板更少；
  **requests 代替 httpx** —— httpx 提供分阶段超时与统一的同步接口，更贴合探测语义。
- **系统读取：解析 netsh 文本** —— 输出随系统语言与版本变化，脆弱且难测；
  **pywin32** —— 重依赖且与 Python 版本绑定；**WMI** —— COM 慢、字段本地化。
  ctypes 直调 API 拿到的是结构化数据，无子进程、免本地化。
- **系统写入：改用 `SetInterfaceDnsSettings` 等 API 直写** —— 行为尚未验证，
  暂不冒险；netsh / powercfg / reg 已验证可用、行为明确，保留并单独评估替换。
- **分发：只发源码 + `pip install`** —— 网络故障时安装也需要网络，形成死锁，
  与产品定位冲突；**Nuitka** —— 本机未装，需另行确认；PyInstaller 已装且够用。

## 后果

- **零依赖卖点消失**：终端用户不能再“下载一个脚本就跑”，源码运行降级为开发者入口。
- **必须以打包 exe 分发**：发布物是 PyInstaller 产物（`NetOptimizer.exe` 无控制台 +
  `netopt.exe` 控制台）；体积、冷启动、杀软误报成为发布关注点。
- **Windows 锁定**：ctypes 结构体与 API 只在 Windows 有意义，测试靠 `FakeSystemApi`
  与合成缓冲区，不承诺跨平台。
- **ctypes 结构体维护成本**：结构布局、字段对齐、32/64 位差异、API 版本都要手工核对，
  并需要解析单测兜底。
- `uv.lock` 入库会带来 diff 噪音，但换来 CI 与本地的可复现安装。
