from apnetscan.utils import (
    local_networks,
    _networks_from_ipconfig,
    _networks_from_ifconfig,
)


def test_local_networks_returns_list():
    nets = local_networks()
    assert isinstance(nets, list)
    for n in nets:
        assert "/" in n


def test_ipconfig_parser_with_sample():
    import ipaddress

    sample = (
        "Ethernet adapter Ethernet:\n"
        "\n"
        "   IPv4 Address. . . . . . : 192.168.1.50\n"
        "   Subnet Mask . . . . . . : 255.255.255.0\n"
    )
    import apnetscan.utils as u
    import subprocess
    from unittest.mock import patch

    def fake_run(*a, **k):
        class R:
            stdout = sample
        return R()

    with patch.object(subprocess, "run", fake_run):
        nets = u._networks_from_ipconfig()
    assert nets == ["192.168.1.0/24"]


def test_ifconfig_parser_ignores_loopback():
    sample = (
        "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
        "\tinet 127.0.0.1 netmask 0xff000000\n"
        "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
        "\tinet 192.168.1.20 netmask 0xffffff00\n"
    )
    import subprocess
    from unittest.mock import patch

    def fake_run(*a, **k):
        class R:
            stdout = sample
        return R()

    with patch.object(subprocess, "run", fake_run):
        nets = _networks_from_ifconfig()
    assert nets == ["192.168.1.0/24"]
