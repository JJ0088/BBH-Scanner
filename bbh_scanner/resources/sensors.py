"""Lettura sensori: temperatura CPU (k10temp), temperatura GPU (nvidia-smi / amdgpu),
carico di sistema e batteria.

Tutto è a tolleranza di guasto: se un sensore o `psutil`/`nvidia-smi` non è disponibile,
la funzione ritorna `None` invece di far crashare. `psutil` è importato pigramente, così
la logica di decisione del governor resta testabile senza dipendenze.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# Nomi hwmon dei sensori termici della CPU, in ordine di preferenza.
_CPU_HWMON_NAMES = ("k10temp", "coretemp", "acpitz", "zenpower")


@dataclass
class SensorReading:
    cpu_temp: Optional[float] = None       # °C
    gpu_temp: Optional[float] = None       # °C (max tra le GPU trovate)
    cpu_load: Optional[float] = None       # % (0-100), attività di sistema
    on_battery: Optional[bool] = None      # True se non alla presa
    battery_percent: Optional[float] = None

    def hottest(self) -> Optional[float]:
        temps = [t for t in (self.cpu_temp, self.gpu_temp) if t is not None]
        return max(temps) if temps else None


# --- psutil (lazy) --------------------------------------------------------- #

def _psutil():
    try:
        import psutil  # type: ignore

        return psutil
    except Exception:
        return None


# --- CPU temp -------------------------------------------------------------- #

def read_cpu_temp() -> Optional[float]:
    ps = _psutil()
    if ps is not None and hasattr(ps, "sensors_temperatures"):
        try:
            temps = ps.sensors_temperatures() or {}
        except Exception:
            temps = {}
        for name in _CPU_HWMON_NAMES:
            entries = temps.get(name)
            if entries:
                # preferisci 'Tctl'/'Tdie' se presenti, altrimenti la prima.
                vals = [e.current for e in entries if e.current]
                labelled = [e.current for e in entries
                            if (e.label or "").lower() in ("tctl", "tdie") and e.current]
                if labelled:
                    return float(labelled[0])
                if vals:
                    return float(max(vals))
    return _read_cpu_temp_hwmon()


def _read_cpu_temp_hwmon() -> Optional[float]:
    """Fallback: legge /sys/class/hwmon senza psutil."""
    base = Path("/sys/class/hwmon")
    if not base.exists():
        return None
    try:
        for hw in base.glob("hwmon*"):
            name_file = hw / "name"
            if not name_file.exists():
                continue
            name = name_file.read_text().strip()
            if name in _CPU_HWMON_NAMES:
                temp_file = hw / "temp1_input"
                if temp_file.exists():
                    return int(temp_file.read_text().strip()) / 1000.0
    except Exception:
        return None
    return None


# --- GPU temp -------------------------------------------------------------- #

def parse_nvidia_smi_temp(output: str) -> Optional[float]:
    """Estrae la prima temperatura da `nvidia-smi --query-gpu=temperature.gpu`."""
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            return float(line.split()[0])
        except (ValueError, IndexError):
            continue
    return None


def read_nvidia_temp() -> Optional[float]:
    try:
        proc = subprocess.run(
            ["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return None
    if proc.returncode != 0:
        return None
    return parse_nvidia_smi_temp(proc.stdout)


def read_amdgpu_temp() -> Optional[float]:
    """Temperatura della GPU integrata AMD via hwmon (best-effort)."""
    base = Path("/sys/class/hwmon")
    if not base.exists():
        return None
    try:
        for hw in base.glob("hwmon*"):
            name_file = hw / "name"
            if name_file.exists() and name_file.read_text().strip() == "amdgpu":
                for tf in ("temp1_input", "temp2_input"):
                    p = hw / tf
                    if p.exists():
                        return int(p.read_text().strip()) / 1000.0
    except Exception:
        return None
    return None


def read_gpu_temp(monitor_nvidia: bool = True) -> Optional[float]:
    temps: List[float] = []
    if monitor_nvidia:
        t = read_nvidia_temp()
        if t is not None:
            temps.append(t)
    amd = read_amdgpu_temp()
    if amd is not None:
        temps.append(amd)
    return max(temps) if temps else None


# --- Carico & batteria ----------------------------------------------------- #

def read_cpu_load(interval: float = 0.5) -> Optional[float]:
    """% CPU di sistema. Misurato quando NON stiamo scansionando ≈ attività utente."""
    ps = _psutil()
    if ps is None:
        # fallback: load average del primo minuto normalizzato sui core
        try:
            import os

            load1 = os.getloadavg()[0]
            cores = os.cpu_count() or 1
            return min(100.0, (load1 / cores) * 100.0)
        except Exception:
            return None
    try:
        return float(ps.cpu_percent(interval=interval))
    except Exception:
        return None


def read_battery() -> tuple[Optional[bool], Optional[float]]:
    ps = _psutil()
    if ps is None or not hasattr(ps, "sensors_battery"):
        return (None, None)
    try:
        bat = ps.sensors_battery()
    except Exception:
        return (None, None)
    if bat is None:
        return (None, None)  # desktop / nessuna batteria
    on_battery = not bat.power_plugged if bat.power_plugged is not None else None
    return (on_battery, float(bat.percent) if bat.percent is not None else None)


def sample_sensors(monitor_nvidia: bool = True,
                   load_interval: float = 0.5) -> SensorReading:
    on_battery, pct = read_battery()
    return SensorReading(
        cpu_temp=read_cpu_temp(),
        gpu_temp=read_gpu_temp(monitor_nvidia=monitor_nvidia),
        cpu_load=read_cpu_load(interval=load_interval),
        on_battery=on_battery,
        battery_percent=pct,
    )
