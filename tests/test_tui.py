import pytest

from apnetscan.models import Host, ScanResult
from apnetscan.tui import build_table


def make_result():
    return ScanResult(
        target="192.168.1.0/24",
        hosts=[
            Host(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", hostname="router"),
            Host(ip="192.168.1.10", mac="aa:bb:cc:00:00:02", os_guess="Windows"),
        ],
    )


def render(table) -> str:
    rich = pytest.importorskip("rich")
    console = rich.console.Console(record=True, width=200)
    console.print(table)
    return console.export_text()


def test_build_table_renders_hosts():
    rendered = render(build_table(make_result(), selected=0))
    assert "192.168.1.1" in rendered
    assert "192.168.1.10" in rendered
    assert "Windows" in rendered


def test_build_table_marker_on_selected():
    rendered = render(build_table(make_result(), selected=1))
    assert "→" in rendered
