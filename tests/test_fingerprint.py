from apnetscan.enrich import guess_os, parse_ping_ttl


def test_guess_os_ranges():
    assert guess_os(None) is None
    assert guess_os(64) == "Linux/Unix/macOS"
    assert guess_os(128) == "Windows"
    assert guess_os(255) == "router/IoT (TTL alto)"
    assert guess_os(20) == "embedded/dispositivo IoT"


def test_guess_os_out_of_range():
    assert guess_os(300) is None


def test_parse_ping_ttl_invalid_ip():
    latency, ttl = parse_ping_ttl("203.0.113.1", timeout=1)
    assert latency is None or ttl is None
