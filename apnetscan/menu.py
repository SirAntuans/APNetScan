"""Menú interactivo de APSoft.

Al abrir la app sin subcomando se muestra un panel con las opciones
disponibles. Usa rich si está instalado; si no, fallback a texto plano.
"""

from __future__ import annotations

import sys
from typing import Callable, Optional

APP_TITLE = "APSoft"

MENU_OPTIONS = [
    ("1", "Escanear red", "Detección de dispositivos (ARP/ping) en la red local o un CIDR"),
    ("2", "Escanear con puertos comunes", "Escaneo + puertos TCP habituales de cada host"),
    ("3", "Escanear rango de puertos", "Especificar rangos: 1-1024, 20-25,80,443..."),
    ("4", "Wake-on-LAN", "Enviar magic packet a una o varias MACs"),
    ("5", "Panel TUI en vivo", "Tabla interactiva con refresco y WOL (requiere rich)"),
    ("6", "Guardar inventario", "Escaneo y guardado en ~/.apnetscan/inventory.json"),
    ("7", "Comparar con inventario", "Mostrar deltas: nuevos, desaparecidos, modificados"),
    ("8", "Modo pasivo", "Escucha ARP sin emitir tráfico (requiere root)"),
    ("0", "Salir", "Cerrar la aplicación"),
]

_BANNER = r"""    _    ____  _   _      _   ____                  
   / \  |  _ \| \ | | ___| |_/ ___|  ___ __ _ _ __  
  / _ \ | |_) |  \| |/ _ \ __\___ \ / __/ _` | '_ \ 
 / ___ \|  __/| |\  |  __/ |_ ___) | (_| (_| | | | |
/_/   \_\_|   |_| \_|\___|\__|____/ \___\__,_|_| |_|
"""


def _has_rich() -> bool:
    try:
        from rich.console import Console  # noqa: F401

        return True
    except ImportError:
        return False


def show_banner() -> None:
    if _has_rich():
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text

        console = Console()
        console.print(Panel(Text(_BANNER.lstrip("\n"), style="bold cyan")))
        console.print(Panel(
            f"[bold]{APP_TITLE}[/bold] — Escáner de dispositivos en red local\n"
            f"[dim]Comandos disponibles: scan · watch · tui · wol · passive[/dim]",
            border_style="cyan",
        ))
    else:
        print(_BANNER.lstrip("\n"))
        print(f"{APP_TITLE} — Escáner de dispositivos en red local")
        print("Comandos disponibles: scan · watch · tui · wol · passive")
        print()


def show_menu() -> None:
    if _has_rich():
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(
            title="Menú principal",
            title_style="bold",
            header_style="bold cyan",
            show_header=True,
        )
        table.add_column("Opción", style="bold yellow", justify="center")
        table.add_column("Acción", style="bold green")
        table.add_column("Descripción", style="dim")
        for key, action, desc in MENU_OPTIONS:
            table.add_row(key, action, desc)
        console.print(table)
        console.print("[dim]Selecciona una opción (número) o un comando directo (scan, wol, tui...). Ctrl+C para salir.[/dim]")
    else:
        print("MENÚ PRINCIPAL")
        print("-------------")
        for key, action, desc in MENU_OPTIONS:
            print(f"  [{key}] {action:<28} {desc}")
        print()
        print("Selecciona una opción (número) o un comando directo (scan, wol, tui...).")


def _prompt() -> str:
    try:
        return input("apsoft> ").strip()
    except (EOFError, KeyboardInterrupt):
        return "0"


def menu_loop(actions: dict[str, Callable[[], int]]) -> int:
    """Bucle del menú. `actions` mapea tecla de MENU_OPTIONS a handler.

    Devuelve el código de salida del último comando ejecutado.
    """
    show_banner()
    exit_code = 0
    while True:
        show_menu()
        choice = _prompt()
        if choice == "":
            continue
        if choice == "0":
            return exit_code
        if choice in actions:
            try:
                exit_code = actions[choice]()
            except KeyboardInterrupt:
                print("\nOperación cancelada.")
            except Exception as exc:
                print(f"Error: {exc}", file=sys.stderr)
        else:
            print(f"Opción no reconocida: {choice}\n", file=sys.stderr)


def main_menu() -> int:
    """Punto de entrada del menú con las acciones por defecto de la app."""
    from . import cli
    from .utils import local_networks

    def _detect_or_ask(extra: list[str] | None = None) -> int:
        extra = extra or []
        nets = local_networks()
        if nets:
            print(f"Redes detectadas: {', '.join(nets)}")
            return cli.main(["scan"] + extra)
        target = input(
            "No se detectaron redes automáticamente.\n"
            "Introduce la red a escanear (ej. 192.168.1.0/24): "
        ).strip()
        if not target:
            print("Sin red objetivo, cancelado.")
            return 1
        return cli.main(["scan", "-t", target] + extra)

    def _do_scan() -> int:
        return _detect_or_ask()

    def _do_scan_ports() -> int:
        return _detect_or_ask(["--common-ports"])

    def _do_scan_range() -> int:
        spec = input("Rango de puertos (ej. 1-1024 o 20-25,80,443): ").strip()
        if not spec:
            print("Rango vacío, cancelado.")
            return 1
        return _detect_or_ask(["--port-range", spec])

    def _do_wol() -> int:
        macs = input("MACs (separadas por espacio): ").strip()
        if not macs:
            print("Sin MACs, cancelado.")
            return 1
        return cli.main(["wol"] + macs.split())

    def _do_tui() -> int:
        return cli.main(["tui"])

    def _do_save() -> int:
        return _detect_or_ask(["--save"])

    def _do_diff() -> int:
        return _detect_or_ask(["--diff"])

    def _do_passive() -> int:
        dur = input("Duración en segundos (30): ").strip() or "30"
        return cli.main(["passive", "--duration", dur])

    actions = {
        "1": _do_scan,
        "2": _do_scan_ports,
        "3": _do_scan_range,
        "4": _do_wol,
        "5": _do_tui,
        "6": _do_save,
        "7": _do_diff,
        "8": _do_passive,
    }
    return menu_loop(actions)


if __name__ == "__main__":
    sys.exit(main_menu())
