"""Governor adattivo: decide quanto lo scanner può spingere, momento per momento.

Regimi:
- **TURBO**   — impostato a mano quando esci di casa: usa tutto il PC, l'unico freno
                è la temperatura.
- **NORMAL**  — regime intermedio (auto).
- **POWERSAVE** — stai usando il PC (o batteria/caldo): footprint minimo, ti lascia lavorare.
- **PAUSED**  — temperatura critica: nessun lavoro finché non si raffredda.

La **temperatura è il limite di sicurezza in tutte le modalità**: anche in TURBO, se
scalda oltre la soglia "hot" si scala di un gradino, e se è "critical" si va in PAUSED.

`decide()` è puro e testabile: prende una lettura sensori + config (+ override manuale)
e ritorna un `ResourcePlan`. La classe `Governor` campiona i sensori e applica `decide()`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from bbh_scanner.config import GovernorConfig
from bbh_scanner.resources.sensors import SensorReading, sample_sensors


class Mode(str, Enum):
    TURBO = "turbo"
    NORMAL = "normal"
    POWERSAVE = "powersave"
    PAUSED = "paused"


@dataclass
class ResourcePlan:
    mode: Mode
    max_concurrency: int
    nice: int
    cooldown_sec: int
    reason: str

    @property
    def can_work(self) -> bool:
        return self.mode is not Mode.PAUSED and self.max_concurrency > 0


def _ge(value: Optional[float], threshold: float) -> bool:
    return value is not None and value >= threshold


def _is_hot(r: SensorReading, cfg: GovernorConfig) -> bool:
    return _ge(r.cpu_temp, cfg.cpu_hot) or _ge(r.gpu_temp, cfg.gpu_hot)


def _is_critical(r: SensorReading, cfg: GovernorConfig) -> bool:
    return _ge(r.cpu_temp, cfg.cpu_critical) or _ge(r.gpu_temp, cfg.gpu_critical)


def _is_cool(r: SensorReading, cfg: GovernorConfig) -> bool:
    # sconosciuto = trattiamo come non-fresco (prudenza) solo per il turbo auto
    return r.cpu_temp is not None and r.cpu_temp <= cfg.cpu_cool


def _is_busy(r: SensorReading, cfg: GovernorConfig) -> bool:
    return _ge(r.cpu_load, cfg.load_busy)


def _is_idle(r: SensorReading, cfg: GovernorConfig) -> bool:
    return r.cpu_load is not None and r.cpu_load < cfg.load_idle


_ORDER = [Mode.PAUSED, Mode.POWERSAVE, Mode.NORMAL, Mode.TURBO]


def _step_down(mode: Mode) -> Mode:
    idx = _ORDER.index(mode)
    return _ORDER[max(0, idx - 1)]


def _plan_for(mode: Mode, cfg: GovernorConfig, reason: str) -> ResourcePlan:
    if mode is Mode.TURBO:
        return ResourcePlan(mode, cfg.turbo_concurrency, cfg.turbo_nice, 0, reason)
    if mode is Mode.NORMAL:
        return ResourcePlan(mode, cfg.normal_concurrency, cfg.normal_nice, 0, reason)
    if mode is Mode.POWERSAVE:
        return ResourcePlan(mode, cfg.powersave_concurrency, cfg.powersave_nice, 0, reason)
    return ResourcePlan(Mode.PAUSED, 0, cfg.powersave_nice, cfg.cooldown_sec, reason)


def decide(reading: SensorReading, cfg: GovernorConfig,
           override: Optional[str] = None) -> ResourcePlan:
    """override ∈ {None|'auto', 'turbo', 'powersave', 'paused'}."""
    if not cfg.enabled:
        return _plan_for(Mode.NORMAL, cfg, "governor-disabilitato")

    override = (override or "auto").lower()

    # 1) Sicurezza termica assoluta: temperatura critica → PAUSED.
    if _is_critical(reading, cfg):
        return _plan_for(Mode.PAUSED, cfg, f"temp critica (hottest={reading.hottest()}°C)")

    # 2) Regime richiesto (manuale o automatico).
    if override == "paused":
        return _plan_for(Mode.PAUSED, cfg, "override:paused")
    if override == "turbo":
        requested, reason = Mode.TURBO, "override:turbo"
    elif override == "powersave":
        requested, reason = Mode.POWERSAVE, "override:powersave"
    else:  # auto
        if reading.on_battery and cfg.powersave_on_battery:
            requested, reason = Mode.POWERSAVE, "batteria"
        elif _is_hot(reading, cfg):
            requested, reason = Mode.POWERSAVE, "temp alta"
        elif _is_busy(reading, cfg):
            requested, reason = Mode.POWERSAVE, f"pc in uso (load={reading.cpu_load}%)"
        elif cfg.turbo_enabled and _is_cool(reading, cfg) and _is_idle(reading, cfg):
            requested, reason = Mode.TURBO, "libero e fresco"
        else:
            requested, reason = Mode.NORMAL, "auto"

    # 3) Clamp termico: anche in TURBO manuale, se fa "hot" (non critico) scala di un gradino.
    if _is_hot(reading, cfg) and requested in (Mode.TURBO, Mode.NORMAL):
        stepped = _step_down(requested)
        return _plan_for(stepped, cfg, f"{reason} + throttle termico (hottest={reading.hottest()}°C)")

    return _plan_for(requested, cfg, reason)


class Governor:
    """Campiona i sensori e produce un ResourcePlan. `sampler` iniettabile per i test."""

    def __init__(self, cfg: GovernorConfig,
                 sampler: Optional[Callable[[], SensorReading]] = None):
        self.cfg = cfg
        self._sampler = sampler or (
            lambda: sample_sensors(monitor_nvidia=cfg.monitor_nvidia)
        )

    def read(self) -> SensorReading:
        return self._sampler()

    def plan(self, override: Optional[str] = None) -> ResourcePlan:
        return decide(self.read(), self.cfg, override=override)
