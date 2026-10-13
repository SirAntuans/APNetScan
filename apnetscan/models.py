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

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "method": self.method,
        }


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
