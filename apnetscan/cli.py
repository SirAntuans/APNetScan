"""Interfaz de línea de comandos de APNetScan."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .export import to_csv, to_json
from .models import ScanResult
from .passive import listen
from .scanner import ScanMethod, Scanner

HEADER = ("IP", "MAC", "FABRICANTE", "HOSTNAME")
COLS = (16, 20, 24, 24)


def _print_table(result: ScanResult) -> None:
    widths = COLS
    print(HEADER[0].ljust(widths[0]), HEADER[1].ljust(widths[1]),
          HEADER[2].ljust(widths[2]), HEADER[3])
    print("-" * (sum(widths) + 3))
    for h in result.hosts:
        print(
            h.ip.ljust(widths[0]),
            (h.mac or "-").ljust(widths[1]),
            (h.vendor or "-").ljust(widths[2]),
            h.hostname or "-",
        )
    print(f"\n{result.count} dispositivo(s) encontrados en {result.target}.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apnetscan",
        description="APNetScan: detector de dispositivos en red local.",
    )
    parser.add_argument("--version", action="version", version=f"apnetscan {__version__}")
    parser.add_argument(
        "-t", "--target",
        nargs="+",
        help="Red(es) a escanear en formato CIDR o IP (p. ej. 192.168.1.0/24).",
    )
    parser.add_argument(
        "--method",
        choices=[m.value for m in ScanMethod],
        default=ScanMethod.AUTO.value,
        help="Método de escaneo: auto, arp o ping (por defecto: auto).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Segundos de espera por red (por defecto: 2).",
    )
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="No resolver hostnames por DNS reverso.",
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="Modo pasivo: escuchar ARP sin enviar tráfico (requiere root).",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Duración del modo pasivo en segundos (por defecto: 30).",
    )
    parser.add_argument("--iface", help="Interfaz de red para el modo pasivo.")
    parser.add_argument("--json", help="Guardar resultados en un fichero JSON.")
    parser.add_argument("--csv", help="Guardar resultados en un fichero CSV.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.passive:
        hosts = listen(duration=args.duration, iface=args.iface)
        result = ScanResult(target="pasivo", hosts=hosts)
    else:
        if not args.target:
            scanner = Scanner(
                method=args.method,
                timeout=args.timeout,
                resolve_names=not args.no_resolve,
            )
            try:
                result = scanner.scan_local()
            except RuntimeError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2
        else:
            scanner = Scanner(
                method=args.method,
                timeout=args.timeout,
                resolve_names=not args.no_resolve,
            )
            result = scanner.scan(args.target)

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


if __name__ == "__main__":
    sys.exit(main())
