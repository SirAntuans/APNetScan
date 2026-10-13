import pytest

from apnetscan.wol import build_magic_packet, normalize_mac, is_valid_mac, send_wol


def test_normalize_mac_formats():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_invalid():
    with pytest.raises(ValueError):
        normalize_mac("zz:bb:cc:dd:ee:ff")
    with pytest.raises(ValueError):
        normalize_mac("aa:bb:cc")


def test_is_valid_mac():
    assert is_valid_mac("aa:bb:cc:dd:ee:ff")
    assert not is_valid_mac("no-mac")


def test_magic_packet_structure():
    pkt = build_magic_packet("aa:bb:cc:dd:ee:ff")
    assert len(pkt) == 102
    assert pkt[:6] == b"\xff" * 6
    assert pkt[6:12] == bytes.fromhex("aabbccddeeff")
    assert pkt[12:18] == bytes.fromhex("aabbccddeeff")
