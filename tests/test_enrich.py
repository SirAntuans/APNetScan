from apnetscan.enrich import port_label, check_ports, enrich_host
from apnetscan.models import Host


def test_port_label_known():
    assert port_label(22) == "22 (ssh)"
    assert port_label(80) == "80 (http)"
    assert port_label(9999) == "9999"


def test_check_ports_on_closed_host():
    assert check_ports("127.0.0.1", [1, 2, 3], timeout=0.2) == []


def test_check_ports_on_open_socket():
    import socket

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert check_ports("127.0.0.1", [port], timeout=0.5) == [port]
    finally:
        server.close()


def test_enrich_host_no_ports():
    host = Host(ip="127.0.0.1")
    result = enrich_host(host, ports=[], with_latency=False)
    assert result.ip == "127.0.0.1"
    assert result.open_ports == []


def test_ports_compact_short():
    from apnetscan.enrich import ports_compact

    assert ports_compact([]) == "-"
    assert ports_compact([80]) == "80"
    assert ports_compact([80, 443]) == "80,443"


def test_ports_compact_truncates():
    from apnetscan.enrich import ports_compact

    many = [21, 22, 53, 80, 139, 443, 445, 3389]
    out = ports_compact(many, max_len=14)
    assert out.startswith("21,")
    shown = len([p for p in out.split(",") if not p.startswith("+")])
    assert out.endswith(f",+{len(many) - shown}")
    assert len(out) <= 14
