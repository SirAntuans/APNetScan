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


def _networks_from_iproutes() -> list[str]:
    """Linux: parsear `ip -4 -o addr show`."""
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
        if not net.is_loopback:
            networks.append(str(net))
    return networks


def _networks_from_ipconfig() -> list[str]:
    """Windows: parsear `ipconfig` (IPv4 + máscara)."""
    import re
    import subprocess

    networks: list[str] = []
    try:
        out = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5, check=True
        ).stdout
    except Exception:
        return networks
    blocks: dict[str, dict] = {}
    current: str | None = None
    for line in out.splitlines():
        if line and not line.startswith(" "):
            current = line.strip()
            blocks.setdefault(current, {})
        elif current:
            ipv4_m = re.search(r"IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
            mask_m = re.search(r"(?:M\u00e1scara|Máscara|Subnet)[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
            if ipv4_m:
                blocks[current]["ip"] = ipv4_m.group(1)
            if mask_m:
                blocks[current]["mask"] = mask_m.group(1)
    for data in blocks.values():
        ip_s, mask = data.get("ip"), data.get("mask")
        if not ip_s or not mask:
            continue
        try:
            addr = ipaddress.ip_address(ip_s)
            mask_int = ipaddress.ip_address(mask).packed
            prefix = sum(bin(b).count("1") for b in mask_int)
            net = ipaddress.ip_network(f"{ip_s}/{prefix}", strict=False)
        except ValueError:
            continue
        if not net.is_loopback:
            networks.append(str(net))
    return networks


def _networks_from_ifconfig() -> list[str]:
    """macOS/BSD: parsear `ifconfig`."""
    import re
    import subprocess

    networks: list[str] = []
    try:
        out = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=5, check=True
        ).stdout
    except Exception:
        return networks
    iface = None
    for line in out.splitlines():
        if line and not line.startswith(("\t", " ")):
            iface = line.split(":")[0]
        if iface in ("lo", "lo0"):
            continue
        m = re.match(r"\s*inet (\d+\.\d+\.\d+\.\d+) netmask (\S+)", line)
        if not m:
            continue
        ip_s, mask_hex = m.group(1), m.group(2)
        try:
            if mask_hex.startswith("0x"):
                mask_int = int(mask_hex, 16)
                prefix = bin(mask_int).count("1")
            else:
                mask = ipaddress.ip_address(mask_hex)
                prefix = sum(bin(b).count("1") for b in mask.packed)
            net = ipaddress.ip_network(f"{ip_s}/{prefix}", strict=False)
        except ValueError:
            continue
        if not net.is_loopback:
            networks.append(str(net))
    return networks


def _networks_from_getenv() -> list[str]:
    """Fallback puro Python: conectar UDP a 8.8.8.8 y ver la IP local."""
    networks: list[str] = []
    try:
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2.0)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        if not net.is_loopback:
            networks.append(str(net))
    except (OSError, ValueError):
        pass
    return networks


def local_networks(ip: Optional[str] = None) -> list[str]:
    """Devuelve los CIDR de las interfaces locales, multiplataforma.

    Orden de intento: Linux `ip` -> Windows `ipconfig` -> macOS `ifconfig`
    -> fallback UDP. Si `ip` se proporciona, filtra la red que la contiene.
    """
    import sys

    networks: list[str] = []
    detectors = [
        _networks_from_iproutes,
        _networks_from_ipconfig,
        _networks_from_ifconfig,
        _networks_from_getenv,
    ]
    for detect in detectors:
        networks = detect()
        if networks:
            break

    if ip:
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return networks
        networks = [
            str(n)
            for n in (ipaddress.ip_network(c) for c in networks)
            if target in n
        ]

    unique: list[str] = []
    for n in networks:
        if n not in unique:
            unique.append(n)
    return unique


def arp_table() -> dict[str, str]:
    """Lee la tabla ARP del sistema operativo y devuelve {ip: mac}.

    Multiplataforma: `ip neigh` (Linux), `arp -a` (Windows/macOS/BSD).
    Requiere que los hosts hayan sido contactados antes (ping) para que
    el sistema haya poblado su cache ARP.
    """
    import re
    import subprocess

    table: dict[str, str] = {}

    def _try(cmd: list[str]) -> str:
        try:
            return subprocess.run(
                cmd, capture_output=True, text=True, timeout=5, check=True
            ).stdout
        except Exception:
            return ""

    out = _try(["ip", "neigh"])
    if not out:
        out = _try(["arp", "-a"])
    if not out:
        return table

    for line in out.splitlines():
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac_m = re.search(
            r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", line
        )
        if not ip_m or not mac_m:
            continue
        ip = ip_m.group(1)
        mac = mac_m.group(0).lower().replace("-", ":")
        parts = mac.split(":")
        if len(parts) == 6:
            mac = ":".join(p.zfill(2) for p in parts)
        if ip in ("127.0.0.1",) or mac.startswith("ff:ff:ff"):
            continue
        table[ip] = mac
    return table
