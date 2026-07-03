"""Configurazione centralizzata, letta da variabili d'ambiente con default sensati.

Tutti i parametri operativi (path, credenziali, budget risorse, intervalli) vivono qui:
si regolano dall'ambiente/modulo NixOS senza toccare il codice.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class HackerOneConfig:
    """Credenziali Hacker API v1 (HTTP Basic: username=token id, password=token)."""

    username: str = field(default_factory=lambda: _env("HACKERONE_API_USERNAME"))
    token: str = field(default_factory=lambda: _env("HACKERONE_API_TOKEN"))
    base_url: str = field(
        default_factory=lambda: _env(
            "HACKERONE_API_BASE", "https://api.hackerone.com/v1/hackers"
        )
    )
    # Rate limit lettura documentato: 600 req/min. Restiamo conservativi.
    max_requests_per_min: int = field(
        default_factory=lambda: _env_int("HACKERONE_RPM", 300)
    )

    @property
    def configured(self) -> bool:
        return bool(self.username and self.token)


@dataclass(frozen=True)
class TelegramConfig:
    bot_token: str = field(default_factory=lambda: _env("TELEGRAM_BOT_TOKEN"))
    chat_id: str = field(default_factory=lambda: _env("TELEGRAM_CHAT_ID"))

    @property
    def configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)


@dataclass(frozen=True)
class ResourceBudget:
    """Vincoli per far girare il tutto su hardware modesto (Acer Aspire 7)."""

    max_concurrency: int = field(default_factory=lambda: _env_int("BBH_MAX_CONCURRENCY", 2))
    nice: int = field(default_factory=lambda: _env_int("BBH_NICE", 10))
    ionice_class: int = field(default_factory=lambda: _env_int("BBH_IONICE_CLASS", 3))
    tool_timeout_sec: int = field(default_factory=lambda: _env_int("BBH_TOOL_TIMEOUT", 1800))
    retention_days: int = field(default_factory=lambda: _env_int("BBH_RETENTION_DAYS", 30))


@dataclass(frozen=True)
class GovernorConfig:
    """Governor termico/adattivo — lo scanner cede il passo quando usi il PC.

    Tre regimi: TURBO (macchina libera e fresca), NORMAL, POWERSAVE (stai usando
    il PC o fa caldo). Se la temperatura è critica → PAUSED (attende il raffreddamento).
    Soglie tarate per Ryzen 7 5700U + RTX 3050; regolabili da env.
    """

    enabled: bool = field(default_factory=lambda: _env_bool("BBH_GOVERNOR", True))
    turbo_enabled: bool = field(default_factory=lambda: _env_bool("BBH_TURBO", True))

    # Temperature (°C)
    cpu_cool: float = field(default_factory=lambda: float(_env_int("BBH_CPU_COOL", 65)))
    cpu_hot: float = field(default_factory=lambda: float(_env_int("BBH_CPU_HOT", 82)))
    cpu_critical: float = field(default_factory=lambda: float(_env_int("BBH_CPU_CRITICAL", 90)))
    gpu_hot: float = field(default_factory=lambda: float(_env_int("BBH_GPU_HOT", 85)))
    gpu_critical: float = field(default_factory=lambda: float(_env_int("BBH_GPU_CRITICAL", 92)))

    # Carico di sistema misurato quando NON stiamo scansionando (= attività utente, %).
    load_idle: float = field(default_factory=lambda: float(_env_int("BBH_LOAD_IDLE", 15)))
    load_busy: float = field(default_factory=lambda: float(_env_int("BBH_LOAD_BUSY", 35)))

    powersave_on_battery: bool = field(
        default_factory=lambda: _env_bool("BBH_POWERSAVE_ON_BATTERY", True)
    )
    cooldown_sec: int = field(default_factory=lambda: _env_int("BBH_COOLDOWN", 120))

    # Concorrenza/nice per regime (8 core: turbo lascia margine all'utente).
    turbo_concurrency: int = field(default_factory=lambda: _env_int("BBH_TURBO_CONC", 4))
    turbo_nice: int = field(default_factory=lambda: _env_int("BBH_TURBO_NICE", 5))
    normal_concurrency: int = field(default_factory=lambda: _env_int("BBH_NORMAL_CONC", 2))
    normal_nice: int = field(default_factory=lambda: _env_int("BBH_NORMAL_NICE", 10))
    powersave_concurrency: int = field(default_factory=lambda: _env_int("BBH_PS_CONC", 1))
    powersave_nice: int = field(default_factory=lambda: _env_int("BBH_PS_NICE", 19))

    # GPU discreta NVIDIA da monitorare via nvidia-smi (RTX 3050).
    monitor_nvidia: bool = field(default_factory=lambda: _env_bool("BBH_MONITOR_NVIDIA", True))


@dataclass(frozen=True)
class Config:
    root: Path
    data_dir: Path
    db_path: Path
    logs_dir: Path
    log_level: str
    log_json: bool
    # Ogni quanto risincronizzare il collector e rifare recon (secondi).
    sync_interval_sec: int
    recon_interval_sec: int
    heartbeat_interval_sec: int
    hackerone: HackerOneConfig
    telegram: TelegramConfig
    budget: ResourceBudget
    governor: GovernorConfig

    @staticmethod
    def load() -> "Config":
        default_root = Path(__file__).resolve().parents[1]
        root = Path(_env("BBH_ROOT", str(default_root)))
        data_dir = Path(_env("BBH_DATA_DIR", str(root / "data")))
        db_path = Path(_env("BBH_DB_PATH", str(data_dir / "store.db")))
        logs_dir = Path(_env("BBH_LOGS_DIR", str(root / "logs")))
        return Config(
            root=root,
            data_dir=data_dir,
            db_path=db_path,
            logs_dir=logs_dir,
            log_level=_env("BBH_LOG_LEVEL", "INFO").upper(),
            log_json=_env_bool("BBH_LOG_JSON", True),
            sync_interval_sec=_env_int("BBH_SYNC_INTERVAL", 6 * 3600),
            recon_interval_sec=_env_int("BBH_RECON_INTERVAL", 24 * 3600),
            heartbeat_interval_sec=_env_int("BBH_HEARTBEAT_INTERVAL", 12 * 3600),
            hackerone=HackerOneConfig(),
            telegram=TelegramConfig(),
            budget=ResourceBudget(),
            governor=GovernorConfig(),
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
