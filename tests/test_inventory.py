import json

from apnetscan.inventory import diff, save
from apnetscan.models import Host, ScanResult


def make_scan(hosts):
    return ScanResult(target="192.168.1.0/24", hosts=hosts)


def test_save_and_roundtrip(tmp_path):
    inv = tmp_path / "inv.json"
    scan = make_scan([Host(ip="192.168.1.1", mac="aa:bb:cc:00:00:01")])
    save(scan, inv)
    data = json.loads(inv.read_text(encoding="utf-8"))
    assert data["count"] == 1
    assert "192.168.1.1" in data["hosts"]


def test_diff_new_and_missing(tmp_path):
    inv = tmp_path / "inv.json"
    old = make_scan([Host(ip="10.0.0.1"), Host(ip="10.0.0.2")])
    save(old, inv)
    new = make_scan([Host(ip="10.0.0.2"), Host(ip="10.0.0.9")])
    d = diff(new, inv)
    assert [h.ip for h in d.new] == ["10.0.0.9"]
    assert [h.ip for h in d.missing] == ["10.0.0.1"]
    assert d.changed == []


def test_diff_changed_mac(tmp_path):
    inv = tmp_path / "inv.json"
    save(make_scan([Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:aa")]), inv)
    new = make_scan([Host(ip="10.0.0.1", mac="bb:bb:bb:bb:bb:bb")])
    d = diff(new, inv)
    assert [h.ip for h in d.changed] == ["10.0.0.1"]


def test_diff_empty_when_identical(tmp_path):
    inv = tmp_path / "inv.json"
    hosts = [Host(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:aa", hostname="h1")]
    save(make_scan(hosts), inv)
    d = diff(make_scan(hosts), inv)
    assert d.is_empty
