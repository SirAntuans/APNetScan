"""Panel TUI interactivo basado en rich.

Requiere el extra `tui` (rich). Ofrece una tabla viva con los dispositivos
detectados, refresco periódico y teclas de acción:

  r  refrescar ahora        w  enviar WOL al dispositivo seleccionado
  q  salir                 ↑/↓ navegar por la lista
"""

from __future__ import annotations

import sys
import time
from typing import Optional

from .models import ScanResult
from .scanner import Scanner

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "El panel TUI requiere rich: pip install apnetscan[tui]"
    ) from exc

APP_TITLE = "APSoft"

KEY_QUIT = "q"
KEY_REFRESH = "r"
KEY_WOL = "w"


def build_table(result: ScanResult, selected: int) -> Table:
    table = Table(
        title=f"{APP_TITLE} — dispositivos detectados ({result.count})",
        title_style="bold cyan",
        header_style="bold",
    )
    for col in ("*", "IP", "MAC", "FABRICANTE", "HOSTNAME", "PUERTOS", "TTL", "SO", "LAT."):
        table.add_column(col, no_wrap=True, overflow="fold")

    for idx, h in enumerate(result.hosts):
        marker = "→" if idx == selected else ""
        ports = ",".join(str(p) for p in h.open_ports) if h.open_ports else "-"
        latency = f"{h.latency_ms:.1f}ms" if h.latency_ms is not None else "-"
        style = "bold yellow" if idx == selected else None
        table.add_row(
            Text(marker, style="bold yellow"),
            Text(h.ip, style=style),
            h.mac or "-",
            (h.vendor or "-")[:22],
            (h.hostname or "-")[:22],
            ports,
            str(h.ttl) if h.ttl is not None else "-",
            h.os_guess or "-",
            latency,
        )
    return table


def _read_key(timeout: float) -> Optional[str]:
    """Lee una tecla sin bloquear demasiado (solo POSIX; en otros entornos None)."""
    try:
        import select
        import termios
        import tty

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            readable, _, _ = select.select([sys.stdin], [], [], timeout)
            if not readable:
                return None
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                rest, _, _ = select.select([sys.stdin], [], [], 0.1)
                if rest:
                    ch2 = sys.stdin.read(2)
                    return {"[A": "up", "[B": "down"}.get(ch2, None)
                return None
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except (ImportError, ValueError, OSError):
        return None


def _render(console: Console, result: ScanResult, selected: int) -> None:
    console.clear()
    console.print(build_table(result, selected))
    console.print(f"[dim]{result.count} dispositivo(s) — {result.target}[/dim]")
    console.print("[dim]r=refrescar  ↑/↓=navegar  w=WOL  q=salir[/dim]")


def run_tui(
    scanner: Scanner,
    targets: Optional[list[str]] = None,
    interval: float = 30.0,
    console: Optional[Console] = None,
    max_loops: Optional[int] = None,
) -> int:
    """Bucle principal del panel TUI. `max_loops` es útil para pruebas."""
    from .wol import send_wol

    console = console or Console()
    selected = 0
    loops = 0

    console.print(Panel(Text(APP_TITLE, style="bold cyan")))

    while True:
        if max_loops is not None and loops >= max_loops:
            return 0
        loops += 1

        result = scanner.scan(targets) if targets else scanner.scan_local()
        selected = max(0, min(selected, max(0, result.count - 1)))
        _render(console, result, selected)

        deadline = time.time() + max(1.0, interval)
        while time.time() < deadline:
            key = _read_key(0.5)
            if key == KEY_QUIT:
                return 0
            if key == "up" and result.hosts:
                selected = max(0, selected - 1)
                _render(console, result, selected)
            elif key == "down" and result.hosts:
                selected = min(result.count - 1, selected + 1)
                _render(console, result, selected)
            elif key == KEY_REFRESH:
                break
            elif key == KEY_WOL and result.hosts and 0 <= selected < result.count:
                host = result.hosts[selected]
                if host.mac:
                    ok = send_wol(host.mac)
                    console.print(
                        f"[green]WOL enviado a {host.mac}[/green]"
                        if ok
                        else f"[red]Error enviando WOL a {host.mac}[/red]"
                    )
                    time.sleep(1)
                    _render(console, result, selected)
