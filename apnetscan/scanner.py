"""Backends de escaneo activo: ARP (scapy) y ping sweep."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from .enrich import enrich_host
from .models import Host, ScanResult
from .utils import lookup_hostname, lookup_vendor


class ScanMethod(str, Enum):
    AUTO = "auto"
    ARP = "arp"
    PING = "ping"


@dataclass
class _ScanContext:
    method: str


def _scapy_available() -> bool:
    try:
        from scapy.all import conf  # noqa: F401

        return True
    except ImportError:
        return False


def _arp_scan(network: str, timeout: float) -> list[Host]:
    """Escaneo ARP con scapy. Requiere privilegios elevados."""
    from scapy.all import ARP, Ether, srp

    net = ipaddress.ip_network(network, strict=False)
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
        timeout=timeout,
        verbose=False,
    )
    hosts: dict[str, Host] = {}
    for _, received in answered:
        ip = received.psrc
        mac = (received.hwsrc or "").lower()
        if ip in hosts:
            continue
        hosts[ip] = Host(
            ip=ip,
            mac=mac,
            vendor=lookup_vendor(mac),
            method="arp",
        )
    return list(hosts.values())


def _ping_one(ip: str, timeout: float) -> bool:
    """Ping multiplataforma a una IP."""
    flag = "-n" if sys.platform.startswith("win") else "-c"
    count = "1"
    tos = "-w" if sys.platform.startswith("win") else "-W"
    secs = str(int(max(1, timeout)))
    cmd = ["ping", flag, count, tos, secs, ip]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _ping_scan(network: str, timeout: float, workers: int = 32) -> list[Host]:
    """Ping sweep sobre un CIDR con pool de hilos.

    Tras el sweep, lee la tabla ARP del SO para asignar MAC a cada IP
    respondida (el ping acaba de poblar la cache ARP del sistema).
    """
    from .utils import arp_table, lookup_vendor

    net = ipaddress.ip_network(network, strict=False)
    ips = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    hosts: list[Host] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_ping_one, ip, timeout): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                ip = futures[future]
                hosts.append(Host(ip=ip, method="ping"))

    table = arp_table()
    for host in hosts:
        mac = table.get(host.ip)
        if mac:
            host.mac = mac
            host.vendor = lookup_vendor(mac)

    hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return hosts


class Scanner:
    """Escáner de dispositivos de red.

    method:
      - "auto": ARP si scapy y privilegios lo permiten, si no ping sweep.
      - "arp": forzar ARP scan.
      - "ping": forzar ping sweep.
    """

    def __init__(
        self,
        method: str = ScanMethod.AUTO.value,
        timeout: float = 2.0,
        resolve_names: bool = True,
        ports: list[int] | None = None,
        with_latency: bool = True,
    ) -> None:
        self.method = ScanMethod(method)
        self.timeout = timeout
        self.resolve_names = resolve_names
        self.ports = ports or []
        self.with_latency = with_latency

    def _effective_method(self, network: str) -> str:
        if self.method == ScanMethod.PING:
            return "ping"
        if self.method == ScanMethod.ARP:
            return "arp"
        return "arp" if _scapy_available() else "ping"

    def _enrich(self, host: Host) -> Host:
        if self.resolve_names and host.hostname is None:
            host.hostname = lookup_hostname(host.ip)
        if host.mac and host.vendor is None:
            host.vendor = lookup_vendor(host.mac)
        return host

    def scan_network(self, network: str) -> list[Host]:
        """Escanea una red en formato CIDR (p. ej. 192.168.1.0/24)."""
        method = self._effective_method(network)
        if method == "arp":
            hosts = _arp_scan(network, self.timeout)
        else:
            hosts = _ping_scan(network, self.timeout)
        return [self._enrich(h) for h in hosts]

    def scan(self, targets: str | Iterable[str]) -> ScanResult:
        """Escanea una o varias redes y devuelve el resultado agregado."""
        if isinstance(targets, str):
            targets = [targets]
        all_hosts: dict[str, Host] = {}
        networks: list[str] = []
        for target in targets:
            net = ipaddress.ip_network(target, strict=False)
            networks.append(str(net))
            for host in self.scan_network(str(net)):
                if host.ip not in all_hosts:
                    all_hosts[host.ip] = host
        hosts = sorted(all_hosts.values(), key=lambda h: ipaddress.ip_address(h.ip))
        if self.ports or self.with_latency:
            from .enrich import enrich_host

            port_timeout = min(0.6, self.timeout / 2)
            for host in hosts:
                enrich_host(
                    host,
                    ports=self.ports,
                    timeout=port_timeout,
                    with_latency=self.with_latency,
                )
        return ScanResult(target=", ".join(networks), hosts=hosts)

    def scan_local(self) -> ScanResult:
        """Escanea automáticamente las redes de las interfaces locales."""
        from .utils import local_networks

        nets = local_networks()
        if not nets:
            raise RuntimeError(
                "No se pudieron detectar redes locales; especifica --target."
            )
        return self.scan(nets)
