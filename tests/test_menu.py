import io
from unittest.mock import patch

from apnetscan import menu


def test_menu_options_wellformed():
    assert len(menu.MENU_OPTIONS) >= 8
    keys = [k for k, _, _ in menu.MENU_OPTIONS]
    assert keys[0] == "1" and keys[-1] == "0"
    assert len(set(keys)) == len(keys)


def test_show_banner_fallback_plain(capsys):
    with patch.object(menu, "_has_rich", return_value=False):
        menu.show_banner()
    out = capsys.readouterr().out
    assert "APSoft" in out
    assert "Escáner" in out


def test_show_menu_fallback_plain(capsys):
    with patch.object(menu, "_has_rich", return_value=False):
        menu.show_menu()
    out = capsys.readouterr().out
    assert "Escanear red" in out
    assert "Wake-on-LAN" in out
    assert "Salir" in out


def test_menu_loop_exit_immediately():
    with patch("builtins.input", side_effect=["0"]):
        code = menu.menu_loop({})
    assert code == 0


def test_menu_loop_dispatches_action():
    calls = []

    def action():
        calls.append(1)
        return 7

    with patch("builtins.input", side_effect=["1", "0"]):
        with patch.object(menu, "show_banner"):
            with patch.object(menu, "show_menu"):
                code = menu.menu_loop({"1": action})
    assert calls == [1]
    assert code == 7


def test_menu_loop_invalid_then_exit():
    with patch("builtins.input", side_effect=["zzz", "0"]):
        with patch.object(menu, "show_banner"):
            with patch.object(menu, "show_menu"):
                code = menu.menu_loop({})
    assert code == 0
