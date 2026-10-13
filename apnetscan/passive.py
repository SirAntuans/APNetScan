"""Modo pasivo: escucha paquetes ARP en la red sin enviar tráfico.

Requiere privilegios de root/administrador y scapy instalado.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from .models import Host
from .utils import lookup_vendor


def listen(
    duration: float = 30.0,
    iface: Optional[str] = None,
    on_host: Optional[Callable[[Host], None]] = None,
) -> list[Host]:
    """Escucha paquetes ARP durante `duration` segundos.

    Registra pares IP/MAC observados en la red (who-has, is-at, etc.).
    Devuelve la lista de hosts únicos detectados.
    """
    try:
        from scapy.all import ARP, sniff
    except ImportError as exc:
        raise RuntimeError(
            "El modo pasivo requiere scapy: pip install apnetscan[arp]"
        ) from exc

    seen: dict[str, Host] = {}

    def _handle(packet) -> None:
        if not packet.haslayer(ARP):
            return
        arp = packet[ARP]
        entries = []
        if arp.op in (1, 2) and arp.psrc:
            entries.append((arp.psrc, arp.hwsrc))
        if arp.op == 1 and arp.pdst:
            entries.append((arp.pdst, None))
        for ip, mac in entries:
            try:
                import ipaddress

                ipaddress.ip_address(ip)
            except ValueError:
                continue
            key = ip
            if key in seen:
                if mac and not seen[key].mac:
                    seen[key].mac = mac.lower()
                    seen[key].vendor = lookup_vendor(mac)
                continue
            host = Host(
                ip=ip,
                mac=mac.lower() if mac else None,
                vendor=lookup_vendor(mac) if mac else None,
                method="passive",
            )
            seen[key] = host
            if on_host:
                on_host(host)

    kwargs = {"store": False, "prn": _handle, "timeout": int(duration)}
    if iface:
        kwargs["iface"] = iface
    sniff(**kwargs)
    return list(seen.values())
