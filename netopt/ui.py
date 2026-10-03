# -*- coding: utf-8 -*-
"""渲染原语 —— 纯字符串函数，不做任何 IO。

**ANSI 码值是冻结契约**：``gui.py`` 用 ``COLOR_TAGS`` 把这些码映射成
tkinter 文本标签，改动码值会同时影响 GUI 配色，改之前先确认。
"""

from __future__ import annotations

RESET = "\033[0m"

# gui.COLOR_TAGS 依赖这些具体码值
_CODES = {
    "green": "92",
    "yellow": "93",
    "red": "91",
    "cyan": "96",
    "bold": "1",
}


def _wrap(name: str, text: object) -> str:
    return f"\033[{_CODES[name]}m{text}{RESET}"


def green(text: object) -> str:
    return _wrap("green", text)


def yellow(text: object) -> str:
    return _wrap("yellow", text)


def red(text: object) -> str:
    return _wrap("red", text)


def cyan(text: object) -> str:
    return _wrap("cyan", text)


def bold(text: object) -> str:
    return _wrap("bold", text)


def bar(fraction: float, width: int = 20) -> str:
    """把 0.0-1.0 的比例画成 ``████░░░░`` 形式的条。

    比例会被夹到 [0, 1]；至少画一格实心，避免 0 分时整行空白看不出位置。
    """
    fraction = min(1.0, max(0.0, fraction))
    filled = max(1, round(fraction * width))
    filled = min(filled, width)
    return "█" * filled + "░" * (width - filled)


def ms(value: float | None, digits: int = 1) -> str:
    """毫秒数值的显示形式，None 显示为 ``-``。"""
    return "-" if value is None else f"{value:.{digits}f}"


def pad(text: str, width: int, align: str = "<") -> str:
    """按**可见宽度**对齐。

    中文字符在等宽终端里占两列，``str.ljust`` 按字符数补齐会导致中文列错位，
    所以这里按 East Asian Width 估算显示宽度。
    """
    visible = display_width(text)
    fill = max(0, width - visible)
    if align == "<":
        return text + " " * fill
    if align == ">":
        return " " * fill + text
    left = fill // 2
    return " " * left + text + " " * (fill - left)


def display_width(text: str) -> int:
    """字符串在等宽终端里的显示列数（宽字符算 2）。"""
    import unicodedata

    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width
