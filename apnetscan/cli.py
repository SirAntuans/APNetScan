"""Interfaz de línea de comandos de APNetScan."""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .display import APP_TITLE, Palette, print_banner, render_table
from .enrich import port_label
from .export import to_csv, to_json
from .models import ScanResult
from .passive import listen
from .scanner import ScanMethod, Scanner
from .wol import normalize_mac, send_wol

HEADERS = ("IP", "MAC", "FABRICANTE", "HOSTNAME", "PUERTOS", "TTL", "SO", "LAT.")


def _print_table(result: ScanResult) -> None:
    palette = Palette(enabled=sys.stdout.isatty())
    rows = []
    for h in result.hosts:
        ports = ",".join(port_label(p) for p in h.open_ports) if h.open_ports else "-"
        latency = f"{h.latency_ms:.1f}ms" if h.latency_ms is not None else "-"
        rows.append([
            h.ip,
            h.mac or "-",
            (h.vendor or "-")[:20],
            (h.hostname or "-")[:20],
            ports,
            str(h.ttl) if h.ttl is not None else "-",
            h.os_guess or "-",
            latency,
        ])
    print(render_table(HEADERS, rows, palette))
    print(f"\n{result.count} dispositivo(s) encontrados en {result.target}.")


def _print_diff(inv_diff) -> None:
    if inv_diff.is_empty:
        print("Sin cambios respecto al inventario guardado.")
        return
    if inv_diff.new:
        print("NUEVOS:")
        for h in inv_diff.new:
            print(f"  + {h.summary()}")
    if inv_diff.missing:
        print("DESAPARECIDOS:")
        for h in inv_diff.missing:
            print(f"  - {h.summary()}")
    if inv_diff.changed:
        print("MODIFICADOS (MAC/hostname):")
        for h in inv_diff.changed:
            print(f"  ~ {h.summary()}")


def _add_scan_options(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "-t", "--target",
        nargs="+",
        help="Red(es) en CIDR o IP (p. ej. 192.168.1.0/24). Vacío = redes locales.",
    )
    sub.add_argument(
        "--method",
        choices=[m.value for m in ScanMethod],
        default=ScanMethod.AUTO.value,
        help="Método: auto, arp o ping (por defecto: auto).",
    )
    sub.add_argument("--timeout", type=float, default=2.0, help="Espera por red (s).")
    sub.add_argument("--no-resolve", action="store_true", help="Sin DNS reverso.")
    sub.add_argument(
        "--ports", nargs="*", type=int, default=None,
        help="Comprobar estos puertos TCP (vacío = no comprobar).",
    )
    sub.add_argument(
        "--common-ports", action="store_true",
        help="Comprobar puertos comunes (21,22,23,25,53,80,...).",
    )
    sub.add_argument(
        "--port-range", metavar="SPEC",
        help="Rango de puertos a comprobar: '80', '1-1024' o '20-25,80,443'.",
    )
    sub.add_argument("--json", help="Guardar resultados en JSON.")
    sub.add_argument("--csv", help="Guardar resultados en CSV.")
    sub.add_argument(
        "--save", action="store_true",
        help="Guardar el escaneo como inventario (~/.apnetscan/inventory.json).",
    )
    sub.add_argument(
        "--diff", action="store_true",
        help="Comparar con el inventario guardado y mostrar cambios.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apsoft",
        description=f"{APP_TITLE}: escáner de dispositivos en red local con WOL.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_TITLE} {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Escanear red(es) y listar dispositivos.")
    _add_scan_options(scan)

    watch = sub.add_parser(
        "watch", help="Re-escanear periódicamente mostrando la lista actualizada."
    )
    _add_scan_options(watch)
    watch.add_argument(
        "--interval", type=float, default=30.0,
        help="Segundos entre escaneos (por defecto: 30).",
    )
    watch.add_argument(
        "--once", action="store_true",
        help="Ejecutar un único escaneo y salir (para pruebas).",
    )

    wol = sub.add_parser("wol", help="Enviar Wake-on-LAN a una o varias MACs.")
    wol.add_argument("macs", nargs="+", help="Direcciones MAC objetivo.")
    wol.add_argument("--ip", default="255.255.255.255", help="IP de broadcast.")
    wol.add_argument("--port", type=int, default=9, help="Puerto UDP (defecto: 9).")
    wol.add_argument("--attempts", type=int, default=3, help="Intentos por MAC.")

    passive = sub.add_parser("passive", help="Modo pasivo: escuchar ARP (root).")
    passive.add_argument("--duration", type=float, default=30.0, help="Segundos.")
    passive.add_argument("--iface", help="Interfaz de red.")
    passive.add_argument("--json", help="Guardar resultados en JSON.")

    tui = sub.add_parser(
        "tui", help="Panel interactivo (requiere rich: pip install apnetscan[tui])."
    )
    tui.add_argument(
        "-t", "--target", nargs="+",
        help="Red(es) en CIDR o IP. Vacío = redes locales.",
    )
    tui.add_argument(
        "--method",
        choices=[m.value for m in ScanMethod],
        default=ScanMethod.AUTO.value,
    )
    tui.add_argument("--timeout", type=float, default=2.0)
    tui.add_argument("--no-resolve", action="store_true")
    tui.add_argument(
        "--interval", type=float, default=30.0,
        help="Segundos entre re-escaneos (por defecto: 30).",
    )
    tui.add_argument(
        "--ports", nargs="*", type=int, default=None,
        help="Comprobar estos puertos TCP en cada host.",
    )
    tui.add_argument("--common-ports", action="store_true")
    tui.add_argument("--port-range", metavar="SPEC", help="'80', '1-1024' o '20-25,80'.")
    return parser


def _resolve_ports(args) -> list[int]:
    from .enrich import COMMON_PORTS, parse_port_range

    if getattr(args, "port_range", None):
        return parse_port_range(args.port_range)
    if args.common_ports:
        return COMMON_PORTS
    return args.ports or []


def _run_scan(args) -> ScanResult:
    ports = _resolve_ports(args)
    scanner = Scanner(
        method=args.method,
        timeout=args.timeout,
        resolve_names=not args.no_resolve,
        ports=ports,
    )
    if args.target:
        return scanner.scan(args.target)
    return scanner.scan_local()


def _post_scan(args, result: ScanResult) -> None:
    from . import inventory

    if result.hosts:
        print_banner()
    _print_table(result)

    if args.diff:
        inv_diff = inventory.diff(result)
        print("\n=== DIFERENCIA CON INVENTARIO ===")
        _print_diff(inv_diff)
    if args.save:
        path = inventory.save(result)
        print(f"Inventario guardado en {path}")
    if args.json:
        to_json(result, args.json)
        print(f"Resultados guardados en {args.json}")
    if args.csv:
        to_csv(result, args.csv)
        print(f"Resultados guardados en {args.csv}")


def _cmd_scan(args) -> int:
    try:
        result = _run_scan(args)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    _post_scan(args, result)
    return 0


def _cmd_watch(args) -> int:
    try:
        print_banner()
        while True:
            print(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} ===")
            try:
                result = _run_scan(args)
            except RuntimeError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2
            _post_scan(args, result)
            if args.once:
                return 0
            time.sleep(max(1.0, args.interval))
    except KeyboardInterrupt:
        print("\nDetenido por el usuario.")
        return 0


def _cmd_wol(args) -> int:
    ok = True
    for mac in args.macs:
        try:
            normalized = normalize_mac(mac)
            if send_wol(mac, ip=args.ip, port=args.port, attempts=args.attempts):
                print(f"WOL enviado a {normalized} ({args.ip}:{args.port})")
            else:
                print(f"Error enviando WOL a {normalized}", file=sys.stderr)
                ok = False
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            ok = False
    return 0 if ok else 1


def _cmd_passive(args) -> int:
    try:
        hosts = listen(duration=args.duration, iface=args.iface)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    result = ScanResult(target="pasivo", hosts=hosts)
    if result.hosts:
        _print_table(result)
    else:
        print("No se detectaron dispositivos.")
    if args.json:
        to_json(result, args.json)
        print(f"Resultados guardados en {args.json}")
    return 0


def _cmd_tui(args) -> int:
    try:
        from .tui import run_tui
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    ports = _resolve_ports(args)
    scanner = Scanner(
        method=args.method,
        timeout=args.timeout,
        resolve_names=not args.no_resolve,
        ports=ports,
    )
    try:
        return run_tui(scanner, targets=args.target, interval=args.interval)
    except KeyboardInterrupt:
        print("\nSaliendo del panel.")
        return 0
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "wol":
        return _cmd_wol(args)
    if args.command == "passive":
        return _cmd_passive(args)
    if args.command == "watch":
        return _cmd_watch(args)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "tui":
        return _cmd_tui(args)
    from .menu import main_menu

    return main_menu()


if __name__ == "__main__":
    sys.exit(main())
