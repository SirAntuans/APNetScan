"""Interfaz de línea de comandos de APNetScan."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .enrich import port_label
from .export import to_csv, to_json
from .models import ScanResult
from .passive import listen
from .scanner import ScanMethod, Scanner
from .wol import normalize_mac, send_wol

HEADER = ("IP", "MAC", "FABRICANTE", "HOSTNAME", "PUERTOS", "LAT.")
COLS = (16, 19, 22, 22, 22, 8)


def _print_table(result: ScanResult) -> None:
    w = COLS
    print(HEADER[0].ljust(w[0]), HEADER[1].ljust(w[1]),
          HEADER[2].ljust(w[2]), HEADER[3].ljust(w[3]),
          HEADER[4].ljust(w[4]), HEADER[5])
    print("-" * (sum(w) + 5))
    for h in result.hosts:
        ports = ",".join(port_label(p) for p in h.open_ports) if h.open_ports else "-"
        latency = f"{h.latency_ms:.1f}ms" if h.latency_ms is not None else "-"
        print(
            h.ip.ljust(w[0]),
            (h.mac or "-").ljust(w[1]),
            (h.vendor or "-")[:22].ljust(w[2]),
            (h.hostname or "-")[:22].ljust(w[3]),
            ports.ljust(w[4]),
            latency,
        )
    print(f"\n{result.count} dispositivo(s) encontrados en {result.target}.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apnetscan",
        description="APNetScan: detector de dispositivos en red local con WOL.",
    )
    parser.add_argument("--version", action="version", version=f"apnetscan {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Escanear red(es) y listar dispositivos.")
    scan.add_argument(
        "-t", "--target",
        nargs="+",
        help="Red(es) en CIDR o IP (p. ej. 192.168.1.0/24). Vacío = redes locales.",
    )
    scan.add_argument(
        "--method",
        choices=[m.value for m in ScanMethod],
        default=ScanMethod.AUTO.value,
        help="Método: auto, arp o ping (por defecto: auto).",
    )
    scan.add_argument("--timeout", type=float, default=2.0, help="Espera por red (s).")
    scan.add_argument("--no-resolve", action="store_true", help="Sin DNS reverso.")
    scan.add_argument(
        "--ports",
        nargs="*",
        type=int,
        default=None,
        help="Comprobar estos puertos TCP (vacío = no comprobar).",
    )
    scan.add_argument(
        "--common-ports",
        action="store_true",
        help="Comprobar los puertos comunes (21,22,23,25,53,80,...).",
    )
    scan.add_argument("--json", help="Guardar resultados en JSON.")
    scan.add_argument("--csv", help="Guardar resultados en CSV.")

    wol = sub.add_parser("wol", help="Enviar Wake-on-LAN a una o varias MACs.")
    wol.add_argument("macs", nargs="+", help="Direcciones MAC objetivo.")
    wol.add_argument("--ip", default="255.255.255.255", help="IP de broadcast.")
    wol.add_argument("--port", type=int, default=9, help="Puerto UDP (defecto: 9).")
    wol.add_argument("--attempts", type=int, default=3, help="Intentos por MAC.")

    passive = sub.add_parser("passive", help="Modo pasivo: escuchar ARP (root).")
    passive.add_argument("--duration", type=float, default=30.0, help="Segundos.")
    passive.add_argument("--iface", help="Interfaz de red.")
    passive.add_argument("--json", help="Guardar resultados en JSON.")
    return parser


def _cmd_scan(args) -> int:
    from .enrich import COMMON_PORTS

    ports: list[int] = []
    if args.common_ports:
        ports = COMMON_PORTS
    elif args.ports:
        ports = args.ports

    scanner = Scanner(
        method=args.method,
        timeout=args.timeout,
        resolve_names=not args.no_resolve,
        ports=ports,
    )
    try:
        if args.target:
            result = scanner.scan(args.target)
        else:
            result = scanner.scan_local()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if result.hosts:
        _print_table(result)
    else:
        print("No se detectaron dispositivos.")

    if args.json:
        to_json(result, args.json)
        print(f"Resultados guardados en {args.json}")
    if args.csv:
        to_csv(result, args.csv)
        print(f"Resultados guardados en {args.csv}")
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "wol":
        return _cmd_wol(args)
    if args.command == "passive":
        return _cmd_passive(args)
    if args.command == "scan":
        return _cmd_scan(args)
    build_parser().parse_args(["scan", "--help"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
