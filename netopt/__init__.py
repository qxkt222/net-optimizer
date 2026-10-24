# -*- coding: utf-8 -*-
"""net-optimizer 核心包（v2）。

分层约定见 ``docs/SPEC.md`` §4：

- ``domain``    —— 纯数据与契约（Report / Policy / 模型），无 IO。
- ``system``    —— 系统边界：ctypes（iphlpapi / wlanapi）、winreg、子进程。
- ``probes*``   —— 组合系统边界与测量，产出领域数据。
- ``analysis``  —— 纯函数：评分、归因、告警规则。
- ``render``    —— 纯函数：Report → 终端 / JSON。
- ``commands``  —— 编排：探测 → Report（不打印）。
- ``cli``       —— 参数解析、渲染、退出码。

版本号以 ``pyproject.toml`` 为发布真值：源码树内直接读取该文件，安装后
从包元数据读取，二者都不可用时回退到 ``_FALLBACK_VERSION``。
"""

from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_PACKAGE_NAME = "net-optimizer"
_FALLBACK_VERSION = "2.0.0.dev0"


def _source_version() -> str | None:
    """读取源码树 ``pyproject.toml`` 的版本；不在源码树时返回 ``None``。

    只有相邻配置确实属于本包时才采用，避免误读上级目录里的其他项目。
    """
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    project = data.get("project")
    if not isinstance(project, dict) or project.get("name") != _PACKAGE_NAME:
        return None
    value = project.get("version")
    return value if isinstance(value, str) and value else None


def _installed_version() -> str | None:
    """已安装发行版的版本；未安装时返回 ``None``。"""
    try:
        return version(_PACKAGE_NAME)
    except PackageNotFoundError:
        return None


# 优先级：源码树 pyproject（开发真值）→ 已安装元数据 → 内置回退。
# 源码运行时必须优先读 pyproject：环境里残留的旧版 dist-info（如 v1.1）
# 会让 ``importlib.metadata`` 返回过期版本，进而与源码实际版本不一致。
__version__ = _source_version() or _installed_version() or _FALLBACK_VERSION

#: 兼容旧接口：``from netopt import VERSION``。
VERSION = __version__

__all__ = ["VERSION", "__version__"]
