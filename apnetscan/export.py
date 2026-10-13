"""Exportación de resultados a JSON y CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import ScanResult

FIELDS = ["ip", "mac", "vendor", "hostname", "method"]


def to_json(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    payload = {"target": result.target, "count": result.count, "hosts": result.as_list()}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def to_csv(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for row in result.as_list():
            writer.writerow({k: row[k] for k in FIELDS})
    return path
