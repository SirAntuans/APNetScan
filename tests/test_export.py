import json
import csv

from apnetscan.export import to_json, to_csv
from apnetscan.models import Host, ScanResult


def make_result():
    return ScanResult(
        target="192.168.1.0/24",
        hosts=[
            Host(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", hostname="router.local"),
            Host(ip="192.168.1.10", mac="aa:bb:cc:00:00:02"),
        ],
    )


def test_json_export(tmp_path):
    result = make_result()
    path = to_json(result, tmp_path / "out.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["count"] == 2
    assert data["hosts"][0]["ip"] == "192.168.1.1"


def test_csv_export(tmp_path):
    result = make_result()
    path = to_csv(result, tmp_path / "out.csv")
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 2
    assert rows[1]["ip"] == "192.168.1.10"
