# -*- coding: utf-8 -*-
"""系统访问层：SystemApi 接口、Fake 实现、实机实现，以及 winreg DNS 读取。

上层只从本包导入 :class:`SystemApi` / :class:`SystemUnavailable` /
:class:`FakeSystemApi` / :class:`LiveSystemApi`；具体 ctypes 模块
（iphlpapi / wlanapi）属于实现细节，由 ``LiveSystemApi`` 组装。
"""

from __future__ import annotations

from netopt.system.api import FakeSystemApi, SystemApi, SystemUnavailable
from netopt.system.live import LiveSystemApi

__all__ = ["FakeSystemApi", "LiveSystemApi", "SystemApi", "SystemUnavailable"]
