"""Inventario persistente: guardado, carga y comparación de escaneos."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import Host, ScanResult

DEFAULT_PATH = Path.home() / ".apnetscan" / "inventory.json"


@dataclass
class InventoryDiff:
    """Cambios entre el inventario guardado y un escaneo nuevo."""

    new: list[Host]
    missing: list[Host]
    changed: list[Host]

    @property
    def is_empty(self) -> bool:
        return not (self.new or self.missing or self.changed)


def _load(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("hosts", {})
    except (json.JSONDecodeError, OSError):
        return {}


def save(result: ScanResult, path: Path = DEFAULT_PATH) -> Path:
    """Guarda el escaneo como inventario {ip: datos}."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    hosts = {h.ip: h.as_dict() for h in result.hosts}
    payload = {"target": result.target, "count": len(hosts), "hosts": hosts}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _to_host(data: dict) -> Host:
    return Host(
        ip=data.get("ip", ""),
        mac=data.get("mac"),
        hostname=data.get("hostname"),
        vendor=data.get("vendor"),
        method=data.get("method"),
        ttl=data.get("ttl"),
        latency_ms=data.get("latency_ms"),
        open_ports=data.get("open_ports", []),
        status=data.get("status", "up"),
        os_guess=data.get("os_guess"),
    )


def diff(result: ScanResult, path: Path = DEFAULT_PATH) -> InventoryDiff:
    """Compara el escaneo con el inventario guardado.

    - new: IPs presentes ahora y no en el inventario.
    - missing: IPs del inventario que ya no responden.
    - changed: IPs presentes en ambos pero con MAC o hostname distintos.
    """
    stored = _load(Path(path))
    current = {h.ip: h for h in result.hosts}

    new = [h for ip, h in current.items() if ip not in stored]
    missing = [_to_host(d) for ip, d in stored.items() if ip not in current]

    changed: list[Host] = []
    for ip, host in current.items():
        if ip not in stored:
            continue
        old = stored[ip]
        if (old.get("mac") or None) != host.mac or (
            old.get("hostname") or None
        ) != host.hostname:
            changed.append(host)

    return InventoryDiff(new=new, missing=missing, changed=changed)
