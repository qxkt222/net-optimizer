# 打包说明

v2 引入运行时依赖（rich / typer / httpx / pydantic），终端用户不再通过
`pip install` 使用，发布物为 PyInstaller 单文件 exe。

## 前置

```bash
uv sync --all-groups
```

## 构建

```bash
# 命令行版：dist/netopt.exe
pyinstaller packaging/netopt.spec

# 图形界面版：dist/NetOptimizer.exe
pyinstaller packaging/netopt-gui.spec
```

## 产物

| 文件 | 入口 | 控制台 |
|---|---|---|
| `dist/netopt.exe` | `netopt/__main__.py` | 有 |
| `dist/NetOptimizer.exe` | `gui.py` | 无 |

## 状态

- 已在 Windows 11 + Python 3.13 + PyInstaller 6.22.3 下实测构建并通过冒烟：
  `netopt.exe version` / `--help` / `ping 127.0.0.1 --json` 均正常。
- 版本号：spec 会把仓库根 `pyproject.toml` 打进包根（onefile 内即 `_MEIPASS`），
  冻结后 `netopt._source_version()` 仍能读到真实版本；**不要从包里删掉该文件**，
  否则会退化成 `_FALLBACK_VERSION`。
- 发布物体积参考：`netopt.exe` 约 16.0 MB，`NetOptimizer.exe` 约 19.1 MB。
- spec 排除了 `pydantic.v1` 与 `pydantic.mypy`（仅开发期使用），避免把
  hypothesis / pytest / setuptools 带进发布物（约省 2.6 MB）。
- GUI 版只能人工双击验证；构建成功且体积合理不代表交互路径已测。
- 首次运行会被 SmartScreen 拦截（无代码签名），属于预期。
- 运行时状态目录：`%LOCALAPPDATA%\net-optimizer`；便携模式见 `--portable`（尚未接入 CLI）。
