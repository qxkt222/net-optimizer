# -*- coding: utf-8 -*-
"""net-optimizer 核心包。

分层约定（重构目标：探测 → 数据 → 渲染）：

- ``models``   —— 纯 dataclass，无任何 IO。
- ``parsers``  —— 纯函数，``str -> models``。所有文本解析的唯一真值点。
- ``platform`` —— 系统边界：子进程执行、提权、控制台初始化。唯一允许碰 os/subprocess 的模块。
- ``probes``   —— 组合 platform + parsers，产出领域数据。
- ``ui``       —— 纯渲染原语（颜色、进度条、对齐），不做 IO。
- ``diag`` / ``fix`` / ``health`` —— 编排：probe -> render -> print。
- ``state``    —— 日志 / 历史 / dev 标志。

可测性约定：凡是要执行系统命令的函数，一律接受可注入的 ``run`` 参数
（见 ``platform.Runner``）。测试用假 runner 注入 fixture 文本，绝不真的调子进程。
"""

VERSION = "1.1"
