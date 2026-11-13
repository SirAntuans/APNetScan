import subprocess
from unittest.mock import patch

from apnetscan import diag
from apnetscan.diag import Adapter, _warnings, diagnose, run_cleanup


def _fake_run(stdout_map):
    def fake_run(cmd, timeout=10.0):
        key = tuple(cmd[:2])
        if cmd[0] in stdout_map:
            return stdout_map[cmd[0]]
        return stdout_map.get(key, "")
    return fake_run


def test_adapters_windows_netsh(monkeypatch):
    monkeypatch.setattr(diag, "_is_windows", lambda: True)
    monkeypatch.setattr(diag.sys, "platform", "win32")
    netsh_out = (
        "Admin State    State         Type             Interface Name\n"
        "-------------  ------------  ---------------  ----------------\n"
        "Enabled        Connected     Dedicated        Wi-Fi\n"
        "Enabled        Disconnected  Dedicated        Ethernet\n"
    )
    ipconfig_out = (
        "Windows IP Configuration\n"
        "Wireless LAN adapter Wi-Fi:\n"
        "   IPv4 Address. . . . . . : 192.168.1.50\n"
    )
    monkeypatch.setattr(
        diag, "_run", _fake_run({"netsh": netsh_out, "ipconfig": ipconfig_out})
    )
    adps = diag.adapters_status()
    names = {a.name: a for a in adps}
    assert names["Wi-Fi"].status == "up"
    assert names["Wi-Fi"].ips == ["192.168.1.50"]
    assert names["Ethernet"].status == "down"


def test_adapters_linux(monkeypatch):
    monkeypatch.setattr(diag, "_is_windows", lambda: False)
    monkeypatch.setattr(diag.sys, "platform", "linux")
    link_out = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
        "3: wlan0: <BROADCAST,MULTICAST> mtu 1500 state DOWN\n"
    )
    addr_out = "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
    monkeypatch.setattr(
        diag,
        "_run",
        _fake_run({("ip", "-o"): link_out, ("ip", "-4"): addr_out}),
    )
    adps = diag.adapters_status()
    names = {a.name: a for a in adps}
    assert names["eth0"].status == "up"
    assert names["eth0"].ips == ["10.0.0.5"]
    assert names["wlan0"].status == "down"


def test_device_problems_windows_wmi(monkeypatch):
    monkeypatch.setattr(diag, "_is_windows", lambda: True)
    monkeypatch.setattr(diag.sys, "platform", "win32")
    ps_out = (
        '"Name","ConfigManagerErrorCode"\n'
        '"Intel(R) Ethernet Connection","28"\n'
        '"Realtek USB GbE Adapter","10"\n'
    )
    monkeypatch.setattr(diag, "_run", _fake_run({"powershell": ps_out}))
    problems = diag.device_problems()
    assert problems[0] == ("Intel(R) Ethernet Connection", "drivers no instalados")
    assert problems[1] == ("Realtek USB GbE Adapter", "el dispositivo no puede iniciarse")


def test_device_problems_non_windows(monkeypatch):
    monkeypatch.setattr(diag, "_is_windows", lambda: False)
    monkeypatch.setattr(diag.sys, "platform", "linux")
    assert diag.device_problems() == []


def test_warnings_up_without_ip():
    warns = _warnings([Adapter(name="wlan0", status="up", ips=[])], [])
    assert any("sin dirección IP" in w for w in warns)


def test_warnings_all_down():
    warns = _warnings([Adapter(name="eth0", status="down")], [])
    assert any("Ningún adaptador" in w for w in warns)


def test_diagnose_structure(monkeypatch):
    monkeypatch.setattr(diag, "adapters_status", lambda: [Adapter(name="e", status="up", ips=["1.2.3.4"])])
    monkeypatch.setattr(diag, "device_problems", lambda: [])
    report = diagnose()
    assert report["adapters"][0]["name"] == "e"
    assert report["problems"] == []


def test_run_cleanup_messages(monkeypatch):
    monkeypatch.setattr(diag, "flush_dns", lambda: (True, "test"))
    monkeypatch.setattr(diag, "flush_arp", lambda: (True, "test"))
    monkeypatch.setattr(diag, "winsock_reset", lambda: (False, "solo Windows"))
    msgs = run_cleanup(do_winsock=True)
    assert len(msgs) == 3
    assert "Flush DNS: OK" in msgs[0]
    assert "Winsock reset: FALLO" in msgs[2]
