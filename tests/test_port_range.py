import pytest

from apnetscan.enrich import parse_port_range, check_ports


def test_single_port():
    assert parse_port_range("80") == [80]


def test_range():
    assert parse_port_range("1-5") == [1, 2, 3, 4, 5]


def test_mixed_spec():
    assert parse_port_range("20-22,80,443") == [20, 21, 22, 80, 443]


def test_dedup_and_sort():
    assert parse_port_range("443,80,443") == [80, 443]


def test_invalid_specs():
    for bad in ["abc", "0-10", "1-70000", "10-2"]:
        with pytest.raises(ValueError):
            parse_port_range(bad)


def test_empty_spec_returns_empty():
    assert parse_port_range("") == []
    assert parse_port_range("  ") == []


def test_check_ports_empty_list():
    assert check_ports("127.0.0.1", []) == []
