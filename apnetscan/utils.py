"""Utilidades de red: resolución de fabricante, hostname e interfaz local."""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from functools import lru_cache
from typing import Optional

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"


@lru_cache(maxsize=1)
def _load_oui_map() -> dict[str, str]:
    """Descarga y parsea el registro OUI de IEEE. Devuelve dict vacío si falla."""
    try:
        with urllib.request.urlopen(OUI_URL, timeout=10) as resp:
            data = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return {}
    mapping: dict[str, str] = {}
    for line in data.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and "(hex)" == parts[1]:
            mac_prefix = parts[0].replace("-", "").lower()
            mapping[mac_prefix] = parts[2].strip()
    return mapping


def lookup_vendor(mac: str) -> Optional[str]:
    """Devuelve el fabricante a partir de los 3 primeros octetos de la MAC."""
    if not mac:
        return None
    prefix = mac.replace(":", "").replace("-", "").lower()[:6]
    return _load_oui_map().get(prefix)


def lookup_hostname(ip: str) -> Optional[str]:
    """Resolución DNS reversa; devuelve None si no hay registro PTR."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


def local_networks(ip: Optional[str] = None) -> list[str]:
    """Devuelve los CIDR de las interfaces locales (o la que contiene `ip`)."""
    import subprocess

    networks: list[str] = []
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        ).stdout
    except Exception:
        return networks
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        cidr = parts[3]
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.is_loopback:
            continue
        if ip:
            try:
                if ipaddress.ip_address(ip) not in net:
                    continue
            except ValueError:
                continue
        if str(net) not in networks:
            networks.append(str(net))
    return networks
