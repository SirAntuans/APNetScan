"""Wake-on-LAN: envío de magic packets (UDP broadcast, puerto 9)."""

from __future__ import annotations

import re
import socket
import struct
from typing import Iterable

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-]?[0-9a-fA-F]{2}){5}$")


def normalize_mac(mac: str) -> str:
    """Normaliza una MAC a formato aa:bb:cc:dd:ee:ff."""
    clean = re.sub(r"[:\s-]", "", mac.strip()).lower()
    if len(clean) != 12 or any(c not in "0123456789abcdef" for c in clean):
        raise ValueError(f"MAC inválida: {mac!r}")
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


def is_valid_mac(mac: str) -> bool:
    return bool(MAC_RE.match(mac.strip()))


def build_magic_packet(mac: str) -> bytes:
    """Construye el magic packet: 6x 0xFF + 16 repeticiones de la MAC."""
    clean = normalize_mac(mac).replace(":", "")
    mac_bytes = bytes.fromhex(clean)
    return b"\xff" * 6 + mac_bytes * 16


def send_wol(
    mac: str,
    ip: str = "255.255.255.255",
    port: int = 9,
    interface: str | None = None,
    attempts: int = 3,
) -> bool:
    """Envía el magic packet por UDP broadcast.

    Devuelve True si se envió al menos un datagrama sin error.
    `interface` permite hacer bind a una interfaz/IP local concreta.
    """
    packet = build_magic_packet(mac)
    sent = False
    for _ in range(max(1, attempts)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(1.0)
                if interface:
                    sock.bind((interface, 0))
                sock.sendto(packet, (ip, port))
                sent = True
        except OSError:
            continue
    return sent


def send_wol_many(
    macs: Iterable[str],
    ip: str = "255.255.255.255",
    port: int = 9,
) -> dict[str, bool]:
    """Envía WOL a varias MACs; devuelve {mac: exito}."""
    return {mac: send_wol(mac, ip=ip, port=port) for mac in macs}
