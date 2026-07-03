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
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
