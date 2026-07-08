"""Minimal ANSI colour console (no third-party dependency)."""

from __future__ import annotations

import os
import sys

_ENABLED = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
)

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
    "red_bg": "\033[41m\033[97m",
    "yellow_bg": "\033[43m\033[30m",
}


def color(text: str, *styles: str) -> str:
    if not _ENABLED or not styles:
        return text
    prefix = "".join(_CODES.get(s, "") for s in styles)
    return f"{prefix}{text}{_CODES['reset']}"


def set_enabled(value: bool) -> None:
    global _ENABLED
    _ENABLED = value


def echo(text: str = "") -> None:
    print(text)


def rule(char: str = "─", width: int = 68) -> None:
    print(color(char * width, "grey"))
