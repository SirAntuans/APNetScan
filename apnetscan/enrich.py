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


def check_ports(
    ip: str,
    ports: list[int],
    timeout: float = 0.5,
    workers: int = 16,
) -> list[int]:
    """Comprueba qué puertos TCP están abiertos en la IP dada."""
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
    """Añade puertos abiertos, servicios y latencia a un host detectado."""
    if ports:
        host.open_ports = check_ports(host.ip, ports, timeout=timeout)
    if with_latency:
        latency, _ = measure_latency(host.ip, timeout=max(timeout, 1.0))
        host.latency_ms = latency
    return host


def port_label(port: int) -> str:
    """Devuelve '22 (ssh)' o '8080' según el puerto."""
    name = PORT_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)
