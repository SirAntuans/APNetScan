"""APNetScan: detector de dispositivos en red local."""

from .models import Host
from .scanner import Scanner, ScanMethod, ScanResult
from .passive import listen
from .wol import send_wol, send_wol_many, build_magic_packet

__version__ = "1.0.0"
__all__ = [
    "Host",
    "Scanner",
    "ScanMethod",
    "ScanResult",
    "listen",
    "send_wol",
    "send_wol_many",
    "build_magic_packet",
]
