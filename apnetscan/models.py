"""Modelos de datos de APNetScan."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Host:
    """Un dispositivo detectado en la red."""

    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    method: Optional[str] = None
    ttl: Optional[int] = None
    latency_ms: Optional[float] = None
    open_ports: list[int] = field(default_factory=list)
    status: str = "up"

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "method": self.method,
            "ttl": self.ttl,
            "latency_ms": self.latency_ms,
            "open_ports": self.open_ports,
            "status": self.status,
        }

    def summary(self) -> str:
        parts = [self.ip]
        if self.mac:
            parts.append(self.mac)
        if self.vendor:
            parts.append(self.vendor)
        if self.hostname:
            parts.append(self.hostname)
        return " | ".join(parts)


@dataclass
class ScanResult:
    """Resultado agregado de un escaneo."""

    target: str
    hosts: list[Host] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.hosts)

    def as_list(self) -> list[dict]:
        return [h.as_dict() for h in self.hosts]

    def macs(self) -> list[str]:
        return [h.mac for h in self.hosts if h.mac]
