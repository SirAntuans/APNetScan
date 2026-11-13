"""Diagnóstico de tarjetas de red y acciones de limpieza.

- Estado de adaptadores (up/down, IP) — multiplataforma
- Problemas de dispositivos de red (Windows: WMI ConfigManagerErrorCode,
  equivalente a ver el triángulo amarillo en el Administrador de dispositivos)
- Limpiezas: flush DNS, flush ARP, winsock reset (Windows, opt-in)
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

WMI_ERROR_LABELS = {
    1: "dispositivo mal configurado",
    10: "el dispositivo no puede iniciarse",
    12: "recursos insuficientes",
    18: "reinstalar drivers",
    21: "Windows está quitando el dispositivo",
    22: "dispositivo deshabilitado",
    28: "drivers no instalados",
    31: "no funciona correctamente (este dispositivo)",
    37: "fallo en el driver",
    43: "Windows detuvo el dispositivo por problemas reportados",
    45: "dispositivo no conectado actualmente",
    52: "no se puede verificar el driver (firma)",
}


@dataclass
class Adapter:
    name: str
    status: str  # "up" | "down" | "desconocido"
    ips: list[str] = field(default_factory=list)
    problem: Optional[str] = None


def _run(cmd: list[str], timeout: float = 10.0) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=True
        )
        return r.stdout
    except Exception:
        return ""


def _is_windows() -> bool:
    return sys.platform.startswith("win")


# ---------------------------------------------------------------- adaptadores


def _adapters_windows() -> list[Adapter]:
    """Windows: netsh interface show interface + ipconfig para IPs."""
    adapters: dict[str, Adapter] = {}
    out = _run(["netsh", "interface", "show", "interface"])
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith(("Admin", "---", "Metodo")):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        # "Enabled  Connected  Dedicated  Wi-Fi" / "Deshabilitado Desconectado..."
        admin, state = parts[0], parts[1]
        name = " ".join(parts[3:])
        status = "up" if "onectado" in state or state.lower() == "connected" else "down"
        adapters[name] = Adapter(name=name, status=status)
    ip_out = _run(["ipconfig"])
    current = None
    for line in ip_out.splitlines():
        if line and not line.startswith(" "):
            current = line.split(":")[0].strip()
        elif current:
            import re

            m = re.search(r"IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
            if not m:
                continue
            for name, adapter in adapters.items():
                if current.endswith(name):
                    adapter.ips.append(m.group(1))
                    break
    return list(adapters.values())


def _adapters_linux() -> list[Adapter]:
    adapters: dict[str, Adapter] = {}
    out = _run(["ip", "-o", "link", "show"])
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name = parts[1].strip().split("@")[0]
        if not name:
            continue
        status = "up" if "state UP" in line or "UP" in line.split(name, 1)[-1][:40] else "down"
        adapters[name] = Adapter(name=name, status=status)
    addr = _run(["ip", "-4", "-o", "addr", "show"])
    for line in addr.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1].rstrip("@").split("@")[0]
        if name in adapters:
            adapters[name].ips.append(parts[3].split("/")[0])
    return list(adapters.values())


def _adapters_macos() -> list[Adapter]:
    import re

    adapters: dict[str, Adapter] = {}
    out = _run(["ifconfig"])
    current = None
    for line in out.splitlines():
        if line and not line.startswith(("\t", " ")):
            name = line.split(":")[0].strip()
            if name:
                current = name
                adapters[name] = Adapter(name=name, status="down")
        elif current:
            m = re.match(r"\s*inet (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                adapters[current].ips.append(m.group(1))
                adapters[current].status = "up"
            if "status: active" in line:
                adapters[current].status = "up"
    return list(adapters.values())


def adapters_status() -> list[Adapter]:
    """Estado de los adaptadores de red del sistema."""
    if _is_windows():
        return _adapters_windows()
    if sys.platform == "darwin":
        return _adapters_macos()
    return _adapters_linux()


# ------------------------------------------------- problemas (Windows Device Mgr)


def device_problems() -> list[tuple[str, str]]:
    """Dispositivos de red con error en el Administrador de dispositivos.

    Solo Windows (WMI). En otros SO devuelve lista vacía.
    Resultado: [(nombre, descripción del problema)]
    """
    if not _is_windows():
        return []
    ps = (
        "Get-CimInstance Win32_NetworkAdapter "
        "| Where-Object { $_.ConfigManagerErrorCode -ne 0 } "
        "| Select-Object Name, ConfigManagerErrorCode "
        "| ConvertTo-Csv -NoTypeInformation"
    )
    out = _run(["powershell", "-NoProfile", "-Command", ps], timeout=30)
    problems: list[tuple[str, str]] = []
    for i, line in enumerate(out.splitlines()):
        line = line.strip()
        if not line or line.startswith('"Name"') or i == 0:
            continue
        parts = [p.strip().strip('"') for p in line.split('","')]
        if len(parts) < 2:
            continue
        try:
            code = int(parts[1])
        except ValueError:
            continue
        label = WMI_ERROR_LABELS.get(code, f"error de configuración (código {code})")
        problems.append((parts[0], label))
    return problems


# ------------------------------------------------------------------- limpiezas


def flush_dns() -> tuple[bool, str]:
    """Limpia la caché DNS del sistema."""
    if _is_windows():
        ok = bool(_run(["ipconfig", "/flushdns"]))
        return ok, "ipconfig /flushdns"
    if sys.platform == "darwin":
        _run(["dscacheutil", "-flushcache"])
        _run(["killall", "-HUP", "mDNSResponder"])
        return True, "dscacheutil + mDNSResponder"
    out = _run(["resolvectl", "flush-caches"]) or _run(
        ["systemd-resolve", "--flush-caches"]
    )
    if out is not None and _run(["which", "resolvectl"]):
        return True, "resolvectl flush-caches"
    return False, "no hay gestor de caché DNS conocido (p. ej. nscd)"


def flush_arp() -> tuple[bool, str]:
    """Limpia la tabla ARP del sistema (requiere root/admin)."""
    if _is_windows():
        ok = bool(_run(["netsh", "interface", "ip", "delete", "arpcache"]))
        return ok, "netsh delete arpcache"
    if sys.platform == "darwin":
        ok = bool(_run(["arp", "-d", "-a"]))
        return ok, "arp -d -a"
    ok = bool(_run(["ip", "neigh", "flush", "all"]))
    return ok, "ip neigh flush all"


def winsock_reset() -> tuple[bool, str]:
    """Reinicia el catálogo Winsock (Windows, requiere reinicio después)."""
    if not _is_windows():
        return False, "solo disponible en Windows"
    ok = bool(_run(["netsh", "winsock", "reset"]))
    return ok, "netsh winsock reset (reinicia el equipo después)"


# -------------------------------------------------------------------- reporte


def diagnose() -> dict:
    """Ejecuta el diagnóstico completo y devuelve un informe."""
    adps = adapters_status()
    problems = device_problems()
    return {
        "adapters": [a.__dict__ for a in adps],
        "problems": [{"name": n, "problem": p} for n, p in problems],
        "warnings": _warnings(adps, problems),
    }


def _warnings(adps: list[Adapter], problems: list[tuple[str, str]]) -> list[str]:
    warns: list[str] = []
    up_adapters = [a for a in adps if a.status == "up"]
    if adps and not up_adapters:
        warns.append("Ningún adaptador de red está activo (up).")
    for a in up_adapters:
        if not a.ips:
            warns.append(f"'{a.name}' está activo pero sin dirección IP (¿DHCP?).")
    for name, problem in problems:
        warns.append(f"Dispositivo con error: '{name}' — {problem}.")
    return warns


def print_report(interactive: bool = False) -> None:
    """Imprime el informe de diagnóstico (con colores si rich está disponible)."""
    adps = adapters_status()
    problems = device_problems()

    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="Adaptadores de red", header_style="bold cyan")
        table.add_column("Adaptador")
        table.add_column("Estado")
        table.add_column("IPs")
        for a in adps:
            state = f"[green]up[/green]" if a.status == "up" else f"[red]{a.status}[/red]"
            table.add_row(a.name, state, ", ".join(a.ips) or "-")
        console.print(table)
        if problems:
            ptable = Table(title="Dispositivos con error (Administrador de dispositivos)", header_style="bold red")
            ptable.add_column("Dispositivo")
            ptable.add_column("Problema")
            for name, problem in problems:
                ptable.add_row(name, f"[red]{problem}[/red]")
            console.print(ptable)
        for w in _warnings(adps, problems):
            console.print(f"[bold red]⚠ {w}[/bold red]")
        if not problems and not _warnings(adps, problems):
            console.print("[green]Sin problemas detectados en tarjetas de red.[/green]")
    except ImportError:
        print("ADAPTADORES DE RED")
        print("-----------------")
        for a in adps:
            print(f"  {a.name:<30} {a.status:<6} {', '.join(a.ips) or '-'}")
        if problems:
            print("\nDISPOSITIVOS CON ERROR")
            print("----------------------")
            for name, problem in problems:
                print(f"  {name}: {problem}")
        for w in _warnings(adps, problems):
            print(f"⚠ {w}")
        if not problems and not _warnings(adps, problems):
            print("Sin problemas detectados en tarjetas de red.")


def run_cleanup(do_dns: bool = True, do_arp: bool = True, do_winsock: bool = False) -> list[str]:
    """Ejecuta limpiezas seleccionadas y devuelve mensajes de resultado."""
    results: list[str] = []
    if do_dns:
        ok, detail = flush_dns()
        results.append(f"Flush DNS: {'OK' if ok else 'FALLO'} ({detail})")
    if do_arp:
        ok, detail = flush_arp()
        results.append(f"Flush ARP: {'OK' if ok else 'FALLO (¿ejecutas como admin/root?)'} ({detail})")
    if do_winsock:
        ok, detail = winsock_reset()
        results.append(f"Winsock reset: {'OK' if ok else 'FALLO'} — {detail}")
    return results
