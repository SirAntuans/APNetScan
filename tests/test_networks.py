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


def test_arp_table_parser_ip_neigh():
    import subprocess
    from unittest.mock import patch

    from apnetscan.utils import arp_table

    sample = (
        "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "192.168.1.10 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
        "192.168.1.20 dev eth0  FAILED\n"
    )

    def fake_run(*a, **k):
        class R:
            stdout = sample
        return R()

    with patch.object(subprocess, "run", fake_run):
        table = arp_table()
    assert table == {
        "192.168.1.1": "aa:bb:cc:dd:ee:ff",
        "192.168.1.10": "11:22:33:44:55:66",
    }


def test_arp_table_parser_windows_arp_a():
    import subprocess
    from unittest.mock import patch

    from apnetscan.utils import arp_table

    sample = (
        "Internet Address      Physical Address      Type\n"
        "  192.168.1.1          a-b-c-d-e-f     dynamic\n"
        "  192.168.1.50         11-22-33-44-55-66    static\n"
    )

    def fake_run_ip(*a, **k):
        raise FileNotFoundError("no ip")

    def fake_run_arp(*a, **k):
        class R:
            stdout = sample
        return R()

    def fake_run(cmd, **k):
        if cmd and cmd[0] == "ip":
            raise FileNotFoundError("no ip")
        return fake_run_arp(cmd, **k)

    with patch.object(subprocess, "run", fake_run):
        table = arp_table()
    assert table["192.168.1.50"] == "11:22:33:44:55:66"
