from apnetscan.models import Host, ScanResult
from apnetscan.scanner import Scanner, ScanMethod


def test_host_as_dict():
    host = Host(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff")
    d = host.as_dict()
    assert d["ip"] == "10.0.0.1"
    assert d["mac"] == "aa:bb:cc:dd:ee:ff"
    assert d["hostname"] is None


def test_scan_result_aggregation():
    result = ScanResult(target="test")
    assert result.count == 0
    assert result.as_list() == []


def test_scanner_accepts_all_methods():
    for method in ScanMethod:
        Scanner(method=method.value)


def test_scanner_rejects_unknown_method():
    try:
        Scanner(method="bogus")
        assert False, "debería lanzar ValueError"
    except ValueError:
        pass
