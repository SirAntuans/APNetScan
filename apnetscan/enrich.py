"""Enriquecimiento de dispositivos: TTL, latencia y puertos abiertos."""

from __future__ import annotations

import concurrent.futures
import socket
import time
from typing import Optional

from .models import Host

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5900, 8080]

PORT_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    3389: "rdp",
    5900: "vnc",
    8080: "http-alt",
}

TTL_RANGES = [
    (0, 33, "embedded/dispositivo IoT"),
    (34, 65, "Linux/Unix/macOS"),
    (66, 129, "Windows"),
    (130, 256, "router/IoT (TTL alto)"),
]


def guess_os(ttl: Optional[int]) -> Optional[str]:
    """Estimación de SO a partir del TTL observado (heurística inicial)."""
    if ttl is None:
        return None
    for low, high, label in TTL_RANGES:
        if low <= ttl < high:
            return label
    return None


def parse_ping_ttl(ip: str, timeout: float = 1.0) -> tuple[Optional[float], Optional[int]]:
    """Ejecuta ping y parsea la salida para obtener (latencia_ms, ttl)."""
    import re
    import subprocess
    import sys

    flag = "-n" if sys.platform.startswith("win") else "-c"
    tos = "-w" if sys.platform.startswith("win") else "-W"
    secs = str(int(max(1, timeout)))
    cmd = ["ping", flag, "1", tos, secs, ip]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, None
    if proc.returncode != 0:
        return None, None
    out = proc.stdout
    time_m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    ttl_m = re.search(r"[Tt][Tt][Ll][=:]\s*(\d+)", out) or re.search(r"ttl\s*=\s*(\d+)", out)
    latency = float(time_m.group(1)) if time_m else None
    ttl = int(ttl_m.group(1)) if ttl_m else None
    return (round(latency, 2) if latency is not None else None), ttl


def measure_latency(ip: str, timeout: float = 1.0) -> tuple[Optional[float], Optional[int]]:
    """Mide latencia TCP (connect al primer puerto abierto o 80/443) y devuelve
    (latencia_ms, None). Usa connect TCP puro, sin privilegios."""
    for port in (80, 443, 22, 445):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                latency = (time.perf_counter() - start) * 1000
                return round(latency, 2), None
        except OSError:
            continue
    return None, None


def parse_port_range(spec: str) -> list[int]:
    """Convierte '80', '1-1024' o '20-25,80,443' en lista de puertos."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, _, high = part.partition("-")
            try:
                lo, hi = int(low), int(high)
            except ValueError:
                raise ValueError(f"Rango de puertos inválido: {part!r}")
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"Rango de puertos inválido: {part!r}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Puerto inválido: {part!r}")
            if not (1 <= p <= 65535):
                raise ValueError(f"Puerto fuera de rango: {part!r}")
            ports.add(p)
    return sorted(ports)


def check_ports(
    ip: str,
    ports: list[int],
    timeout: float = 0.5,
    workers: int = 16,
) -> list[int]:
    """Comprueba qué puertos TCP están abiertos en la IP dada."""
    if not ports:
        return []
    open_ports: list[int] = []

    def _check(port: int) -> Optional[int]:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return port
        except OSError:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(_check, ports):
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)


def enrich_host(
    host: Host,
    ports: list[int],
    timeout: float = 0.5,
    with_latency: bool = True,
) -> Host:
    """Añade puertos abiertos, servicios, latencia, TTL y estimación de SO."""
    if ports:
        host.open_ports = check_ports(host.ip, ports, timeout=timeout)
    if with_latency:
        latency, _ = measure_latency(host.ip, timeout=max(timeout, 1.0))
        host.latency_ms = latency
        ping_latency, ttl = parse_ping_ttl(host.ip, timeout=max(timeout, 1.0))
        if ttl is not None:
            host.ttl = ttl
        elif latency is None and ping_latency is not None:
            host.latency_ms = ping_latency
        if host.ttl is not None and host.os_guess is None:
            host.os_guess = guess_os(host.ttl)
    return host


def port_label(port: int) -> str:
    """Devuelve '22 (ssh)' o '8080' según el puerto."""
    name = PORT_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)


def ports_compact(open_ports: list[int], max_len: int = 18) -> str:
    """Representación compacta de puertos para tablas: números y truncado.

    Ejemplos: '21,22,53,80', '80,139,443,+3', '-'
    """
    if not open_ports:
        return "-"
    items = [str(p) for p in open_ports]
    out = ",".join(items)
    if len(out) <= max_len:
        return out
    shown: list[str] = []
    total = 0
    for it in items:
        if total + len(it) + 1 > max_len - 3:
            break
        shown.append(it)
        total += len(it) + 1
    rest = len(items) - len(shown)
    return ",".join(shown) + f",+{rest}"
