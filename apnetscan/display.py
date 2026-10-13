"""Render de tablas tipo panel con box-drawing y colores ANSI.

Sin dependencias externas: solo stdlib. Los caracteres ANSI se omiten
automáticamente si la salida no es una TTY (estable en CI, logs y pipes).
"""

from __future__ import annotations

import os
import sys
from typing import Iterable, Sequence

APP_TITLE = "APSoft"

STYLES = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "reset": "\033[0m",
}

BANNER = r"""
    _    ____  ____    _    ___ _
   / \  |  _ \|  _ \  / \  / __(_)_ __ ___
  / _ \ | |_) | |_) |/ _ \| |  | | '_ ` _ \
 / ___ \|  __/|  __ / ___ \ |__| | | | | | |
/_/   \_\_|   |_| /_/   \_\___|_|_| |_| |_|
"""


class Palette:
    """Aplica estilos ANSI solo cuando la salida es interactiva."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def wrap(self, text: str, style: str) -> str:
        if not self.enabled or style not in STYLES:
            return text
        return f"{STYLES[style]}{text}{STYLES['reset']}"


def _term_palette() -> Palette:
    return Palette(enabled=sys.stdout.isatty() and os.environ.get("TERM") != "dumb")


def print_banner(palette: Palette | None = None) -> None:
    palette = palette or _term_palette()
    print(palette.wrap(BANNER.lstrip("\n"), "cyan"))
    print(palette.wrap(f"{APP_TITLE} — Escáner de dispositivos en red", "bold"))
    print()


def _visible_len(text: str) -> int:
    import re

    return len(re.sub(r"\033\[[0-9;]*m", "", text))


def render_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[str]],
    palette: Palette | None = None,
) -> str:
    """Devuelve la tabla como string con bordes tipo panel."""
    palette = palette or _term_palette()
    rows = [[str(c) for c in row] for row in rows]
    if not rows:
        return "No se detectaron dispositivos."

    ncols = len(headers)
    widths = [
        max(_visible_len(headers[i]), max((_visible_len(r[i]) for r in rows), default=0))
        for i in range(ncols)
    ]

    def fmt_row(cells: Sequence[str]) -> str:
        padded = []
        for i, cell in enumerate(cells):
            pad = widths[i] - _visible_len(cell)
            padded.append(cell + " " * max(0, pad))
        return "│ " + " │ ".join(padded) + " │"

    sep_top = "┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    sep_mid = "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    sep_bot = "└" + "┴".join("─" * (w + 2) for w in widths) + "┘"

    lines = [sep_top, palette.wrap(fmt_row(headers), "bold"), sep_mid]
    lines.extend(fmt_row(row) for row in rows)
    lines.append(sep_bot)
    return "\n".join(lines)
