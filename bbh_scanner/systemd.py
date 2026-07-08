"""Integrazione systemd (sd_notify) — senza dipendenze.

Se il processo gira sotto systemd con `Type=notify`, `NOTIFY_SOCKET` è impostato e
possiamo mandare READY/WATCHDOG/STOPPING. Fuori da systemd è un no-op silenzioso.
"""

from __future__ import annotations

import os
import socket


def _notify(state: str) -> bool:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    try:
        # I socket "astratti" iniziano con @ → prefisso NUL.
        if addr.startswith("@"):
            addr = "\0" + addr[1:]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.connect(addr)
            sock.sendall(state.encode("utf-8"))
            return True
        finally:
            sock.close()
    except Exception:
        return False


def notify_ready() -> bool:
    return _notify("READY=1")


def notify_watchdog() -> bool:
    return _notify("WATCHDOG=1")


def notify_stopping() -> bool:
    return _notify("STOPPING=1")
