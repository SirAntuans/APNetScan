from apnetscan.display import Palette, render_table


def test_render_table_basic():
    out = render_table(["IP", "MAC"], [["10.0.0.1", "aa:bb"], ["10.0.0.2", "cc:dd"]])
    assert "10.0.0.1" in out and "aa:bb" in out
    assert out.count("│") >= 8


def test_render_table_empty():
    assert "No se detectaron dispositivos." == render_table(["IP"], [])


def test_render_table_has_borders():
    out = render_table(["A", "B"], [["x", "y"]])
    assert out.startswith("┌") and out.endswith("┘")
    assert "┬" in out and "┼" in out and "┴" in out


def test_palette_disabled_strips_ansi():
    p = Palette(enabled=False)
    assert p.wrap("texto", "bold") == "texto"


def test_palette_enabled_wraps():
    p = Palette(enabled=True)
    assert "\033[1m" in p.wrap("texto", "bold")


def test_visible_len_ignores_ansi():
    import re

    from apnetscan.display import _visible_len

    text = "\033[1mhola\033[0m"
    assert _visible_len(text) == 4
