# -*- coding: utf-8 -*-
"""``python -m netopt`` 入口。

包装 :func:`netopt.cli.main`：它返回退出码而不是直接 ``sys.exit``，
因此这里用 ``SystemExit`` 把退出码交给解释器。
"""

from __future__ import annotations

from netopt.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
