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
