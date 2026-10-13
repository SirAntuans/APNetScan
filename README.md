# APNetScan

Escáner de dispositivos en red local escrito en Python.

## Características

- **Detección de hosts** mediante ARP scan (scapy) con fallback a ping sweep.
- **Identificación de fabricante** a partir de la dirección MAC (OUI de IEEE).
- **Detección de hostname** por DNS reverso.
- **Modo pasivo**: escucha ARP en la red sin enviar tráfico (requiere root).
- **Exportación** de resultados a JSON y CSV.
- CLI sencilla con argparse; también usable como librería Python.

## Instalación

```bash
pip install .
```

Con el backend ARP (recomendado):

```bash
pip install .[arp]
```

## Uso

```bash
# Escanear la red a la que pertenece una IP (auto-detecta interfaz y CIDR)
apnetscan --target 192.168.1.1

# Escanear un rango CIDR concreto
apnetscan --target 192.168.1.0/24

# Escanear varias redes
apnetscan --target 192.168.1.0/24 10.0.0.0/24

# Solo ping sweep (sin scapy)
apnetscan --target 192.168.1.0/24 --method ping

# Modo pasivo (escucha ARP durante 60 s, requiere root)
apnetscan --passive --duration 60

# Exportar resultados
apnetscan --target 192.168.1.0/24 --json out.json --csv out.csv
```

Salida de ejemplo:

```
IP                MAC                FABRICANTE              HOSTNAME
192.168.1.1       aa:bb:cc:dd:ee:ff  Vendor Name             router.local
192.168.1.10      11:22:33:44:55:66  Other Vendor             laptop.local
```

## Como librería

```python
from apnetscan import Scanner

scanner = Scanner(method="arp")
results = scanner.scan("192.168.1.0/24")
for host in results:
    print(host.ip, host.mac, host.vendor)
```

## Requisitos

- Python 3.9+
- El escaneo ARP y el modo pasivo requieren privilegios de root/administrador
  (acceso a sockets raw).

## Aviso legal

Usa APNetScan únicamente en redes propias o para las que tengas autorización.
Escanear redes de terceros sin permiso puede ser ilegal.

## Novedades v0.3.0

- **Estimación de SO por TTL** (Windows / Linux-Unix-macOS / IoT) en cada host detectado.
- **Inventario persistente** (`scan --save`) en `~/.apnetscan/inventory.json` con
  comparación de deltas (`scan --diff`): dispositivos nuevos (+), desaparecidos (-)
  y modificados (~) en MAC o hostname.
- **Modo watch** (`apnetscan watch -t 192.168.1.0/24 --interval 30`): re-escanea
  periódicamente y refresca la lista de dispositivos.
